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
COPY run-tests.sh ./
RUN chmod 005 ./run-tests.sh
USER test

ENTRYPOINT ["./run-tests.sh"]
