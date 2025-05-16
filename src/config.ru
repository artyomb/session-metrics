# frozen_string_literal: true
require 'bundler/setup'
require 'sinatra'
require 'securerandom'
require 'json'
require 'socket'
require 'sequel'
require 'faraday'
require 'prometheus/client'
require 'prometheus/middleware/exporter'
require 'rack/timeout'
require 'rack/attack'

# ─── constants & env ─────────────────────────────────────────────────────
COOKIE       = 'sess'.freeze
IDLE_SEC     = Integer(ENV.fetch('IDLE_SEC',        900))          # 15 min
UPSTREAM     = ENV.fetch('UPSTREAM',  'http://backend:3000')
POOL_SIZE    = Integer(ENV.fetch('POOL',            10))
DB_URL       = ENV.fetch('DB_URL',     'sqlite://sessions.db')
SSL_VERIFY   = ENV.fetch('SSL_VERIFY', 'true') == 'true'
INSTANCE     = ENV.fetch('INSTANCE',   Socket.gethostname)
REQ_TIMEOUT  = Integer(ENV.fetch('REQUEST_TIMEOUT', 15))

# ─── Rack::Timeout & Rack::Attack ────────────────────────────────────────
Rack::Timeout.service_timeout = REQ_TIMEOUT

class Rack::Attack
  throttle('req/ip', limit: 100, period: 60) { |req| req.ip }
end

# ─── Database (Sequel) ───────────────────────────────────────────────────
DB = Sequel.connect(DB_URL)
DB.run 'PRAGMA journal_mode=WAL;' if DB.database_type == :sqlite
DB.create_table? :sessions do
  String   :token, primary_key: true
  DateTime :updated_at, null: false, index: true
end
SESS = DB[:sessions]

# ─── Prometheus registry & metrics ───────────────────────────────────────
REG       = Prometheus::Client.registry
ACTIVE_G  = REG.gauge(:web_sessions_active,
                      docstring: 'sessions active within IDLE_SEC seconds',
                      labels: [:instance])
TOTAL_C   = REG.counter(:web_sessions_total,
                        docstring: 'lifetime session tokens issued',
                        labels:   [:instance])
LAT_HIST  = REG.histogram(:upstream_latency_seconds,
                          docstring: 'latency to upstream',
                          labels:   [:instance])

# ─── Background refresh thread — use DB.synchronize, clean shutdown ──────
shutdown = false
%w[TERM INT].each { |sig| Signal.trap(sig) { shutdown = true } }

Thread.new do
  loop do
    break if shutdown
    DB.synchronize do
      threshold = Time.now - IDLE_SEC
      ACTIVE_G.set({instance: INSTANCE}, SESS.where { updated_at > threshold }.count)
      SESS.where { updated_at < threshold }.delete
    end
    sleep 10
  end
end

# ─── Faraday pooled connection ─────────────────────────────────────────--
CONN = Faraday.new(url: UPSTREAM, ssl: { verify: SSL_VERIFY }) do |f|
  f.request :retry, max: 2, interval: 0.05, backoff_factor: 2
  f.options.timeout      = 5
  f.options.open_timeout = 2
  f.adapter :net_http_persistent, pool_size: POOL_SIZE, idle_timeout: 60
end

helpers do
  def issue_token
    tkn = SecureRandom.hex(16)
    response.set_cookie COOKIE,
                        value:     tkn,
                        path:      '/',
                        http_only: true,
                        secure:    request.ssl?,
                        same_site: :lax,
                        max_age:   31_536_000
    TOTAL_C.increment(labels: {instance: INSTANCE})
    tkn
  end

  def touch_session(tkn)
    now = Time.now
    SESS.insert_conflict(target: :token, update: { updated_at: now })
        .insert(token: tkn, updated_at: now)
  end

  def forwarded_headers
    hdrs = Rack::Utils::HeaderHash.new
    env.each do |k, v|
      next unless k.start_with?('HTTP_') || %w[CONTENT_TYPE CONTENT_LENGTH].include?(k)
      hdrs[k.sub(/^HTTP_/, '').split('_').map(&:capitalize).join('-')] = v
    end
    hdrs.delete('Host')

    hdrs['X-Forwarded-For']   = [hdrs['X-Forwarded-For'], request.ip].compact.join(', ')
    hdrs['X-Forwarded-Proto'] = request.scheme
    hdrs['X-Forwarded-Host']  ||= request.host
    hdrs
  end

  def forward_request!
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    resp = CONN.run_request(request.request_method.downcase.to_sym,
                            request.fullpath,
                            request.body.read,
                            forwarded_headers)

    latency = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
    LAT_HIST.observe({instance: INSTANCE}, latency)

    status  resp.status
    headers resp.headers.to_h
    body    resp.body
  rescue Faraday::Error => e
    warn "[proxy] upstream error: #{e.class}: #{e.message}"
    latency = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start rescue nil
    LAT_HIST.observe({instance: INSTANCE}, latency) if latency

    status 502
    if request.env['HTTP_ACCEPT']&.include?('application/json')
      headers 'Content-Type' => 'application/json'
      body   JSON.dump(error: 'Bad Gateway', class: e.class.to_s, message: e.message)
    else
      headers 'Content-Type' => 'text/plain'
      body   "Bad Gateway (#{e.class}) — #{e.message}"
    end
  end
end

set :logging, false
disable :protection, :sessions

# health-check
get '/healthcheck' do
  'pong'
end

# catch-all proxy
route '*', via: :all do
  token = request.cookies[COOKIE] || issue_token
  touch_session(token)
  forward_request!
end

# ─── Middleware stack ────────────────────────────────────────────────────
use Rack::Timeout
use Rack::Attack
use Prometheus::Middleware::Exporter, registry: REG

run Sinatra::Application
