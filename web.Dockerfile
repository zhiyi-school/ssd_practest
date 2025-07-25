FROM node:14

# Create a non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /usr/src/app

# Copy package files and install dependencies as root
COPY package*.json ./
RUN npm install --ignore-scripts

# Copy application files
COPY ./src/public ./public
COPY ./src/server.js .
COPY ./src/utils ./utils
COPY ./src/data ./data

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appuser /usr/src/app

# Switch to non-root user
USER appuser

EXPOSE 80

CMD ["node", "server.js"]