FROM node:24-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production

# iptables on modern Alpine normally uses the nftables compatibility backend.
RUN apk add --no-cache iptables ip6tables conntrack-tools iproute2 wireguard-tools procps busybox-extras

COPY package*.json ./
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist

EXPOSE 8081
CMD ["node", "dist/index.js"]
