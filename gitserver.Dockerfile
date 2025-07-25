FROM node:alpine

RUN apk add --no-cache tini git \
    && yarn global add git-http-server \
    && adduser -D -g git git

# Create necessary directories
RUN mkdir -p /var/git /home/git/.ssh && \
    chown -R git:git /var/git /home/git

USER git
WORKDIR /home/git

# Initialize a bare repository
RUN git init --bare labquiz-repo.git && \
    cd labquiz-repo.git && \
    git config user.name "TAY ZHI YI" && \
    git config user.email "2301807@SIT.singaporetech.edu.sg"


ENTRYPOINT ["tini", "--", "git-http-server", "-p", "3000", "/home/git"]
