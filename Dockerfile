FROM node:22-alpine

WORKDIR /ca-backend

# Create a new user 'test' to avoid running as root
RUN adduser --disabled-password test && chown test .

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts \
    && apk update && apk add --no-cache bash aws-cli && aws --version

# Copy the test files and the configuration files
COPY tests/integrationTests ./tests/integrationTests
COPY vitest.config.ts cucumber.json tsconfig.json ./

# Give user, 'test', permissions to execute test script and switch the user to 'test'
COPY run-tests.sh /
RUN chmod +x /run-tests.sh
RUN ls -la /run-tests.sh

RUN echo "=== DEBUG INFO ===" && \
    pwd && \
    echo "Files in root (/):" && \
    ls -la / && \
    echo "Files in current dir:" && \
    ls -la . && \
    echo "Looking for run-tests.sh:" && \
    find / -name "run-tests.sh" -type f 2>/dev/null || echo "run-tests.sh not found anywhere"

USER test

ENTRYPOINT ["/run-tests.sh"]
