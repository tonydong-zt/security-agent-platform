FROM node:20-alpine AS build

WORKDIR /app
COPY frontend/package.json frontend/tsconfig.json frontend/index.html /app/
COPY frontend/src /app/src
RUN npm install
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
