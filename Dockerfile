# docker build . -t ret
# docker run -p 80:80 ret

ARG NODE_VERSION=22.16.0

FROM debian:latest AS ret_src

ARG NODE_VERSION

RUN mkdir /root/ ; cd /root

WORKDIR /root


RUN apt update && apt install -y cmake ninja-build git sudo tar gpg python3 npm wget

RUN apt install -y python-is-python3

RUN sudo npm cache clean -f ; sudo npm install -g n ; sudo n $NODE_VERSION

COPY . .

RUN git submodule update --init --recursive

RUN git clone https://github.com/emscripten-core/emsdk.git

RUN cd emsdk ; ./emsdk install latest ; ./emsdk activate latest

RUN make CMAKE=/root/emsdk/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake config_all -j`nproc` ;  make CMAKE=/root/emsdk/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake build_all

RUN make deploy

# Start from a basic nginx image
FROM nginx:1.27.4-alpine-slim

RUN rm -rf /usr/share/nginx/html

COPY --from=ret_src /root/deploy /usr/share/nginx/html

RUN mkdir -p /var/cache/nginx ; chown -R nginx:nginx /var/cache/nginx

RUN touch /var/run/nginx.pid ; chown nginx:nginx /var/run/nginx.pid

USER nginx

CMD ["nginx","-g","daemon off;"]
