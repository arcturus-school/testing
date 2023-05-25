FROM node:20-buster-slim as build-stage

WORKDIR /app

COPY . .

RUN npm config set registry https://registry.npmmirror.com
RUN npm install
RUN npm run build

FROM nginx:1.25.0-alpine-slim as production-stage

COPY --from=build-stage /app/dist /usr/share/nginx/html
COPY --from=build-stage /app/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
