# MOMUS frontend — the landing + live panel (built static, served by nginx).
# Build from momus/frontend/:  docker build -t momus-frontend .
# In the deployed topology the outer TLS edge routes API paths (/health, /scan,
# /findings, /intel, /providers, /selfaudit) to the MOMUS backend and everything
# else here; this container only serves the static SPA on port 80.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
