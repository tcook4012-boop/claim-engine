# PrintReadyArt claim engine + vendor portal.
# Node runs the app; Python is here only so the DST checker (dst_check.py) can decode
# embroidery files with pyembroidery and render previews with Pillow. Railway auto-detects
# this Dockerfile and builds from it -- no dashboard config needed.

FROM node:20-slim

# Python + the two libraries the DST checker needs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && pip3 install --no-cache-dir --break-system-packages pyembroidery pillow \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install node deps first for layer caching.
COPY package*.json ./
RUN npm install --omit=dev

# App source.
COPY . .

# Railway provides PORT; app.js reads process.env.PORT.
EXPOSE 3000
CMD ["node", "app.js"]
