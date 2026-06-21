# syntax=docker/dockerfile:1

FROM node:24-bookworm AS web-build
WORKDIR /src
COPY package.json package-lock.json* ./
RUN npm ci
COPY index.html vite.config.js ./
COPY web ./web
RUN npm run build

FROM golang:1.23-bookworm AS go-build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=web-build /src/internal/server/dist ./internal/server/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/alipay-kyc ./cmd/alipay-kyc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go-build /out/alipay-kyc /alipay-kyc
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/alipay-kyc"]
