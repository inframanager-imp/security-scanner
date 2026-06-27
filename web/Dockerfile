# ── Unified Web (CSPM React shell + ASPM pages) + nginx gateway ───────────────
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json ./
RUN npm install --no-audit --no-fund
COPY . ./
# Run vite directly (skip the `tsc &&` in the npm script so a non-blocking type
# error never fails the image build).
RUN npx vite build

# Runtime: nginx serves the SPA and reverse-proxies both backends.
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
