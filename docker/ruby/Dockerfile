# -------- build stage -------------------------------------------------
FROM ruby:3.3-alpine AS build

# base libs + headers for native gems
RUN apk add --no-cache --virtual .build-deps \
      build-base sqlite-dev postgresql-dev tzdata git

WORKDIR /app

# Gem dependencies
COPY Gemfile Gemfile.lock ./
RUN bundle config set --local deployment 'true' && \
    bundle config set --local without 'development test' && \
    bundle install --jobs 4 --retry 3

# copy app code
COPY . .

# -------- runtime stage ----------------------------------------------
FROM ruby:3.3-alpine

# runtime libs only
RUN apk add --no-cache sqlite-libs postgresql-libs tzdata

ENV RACK_ENV=production \
    PORT=9394

WORKDIR /app

# copy ruby + gems from build stage
COPY --from=build /usr/local/bundle /usr/local/bundle
COPY --from=build /app /app

EXPOSE ${APP_PORT}

# health-check: exporter must answer
HEALTHCHECK CMD wget -qO- http://127.0.0.1:${PORT}/metrics || exit 1

ENTRYPOINT ["rackup", "-p", "9394", "-o", "0.0.0.0"]
