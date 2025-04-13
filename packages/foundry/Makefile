include .env

# Define variables (optional)
SRC_DIR := ./src
BUILD_DIR := ./out
TEST_DIR := ./test

.PHONY: test test-coverage


# Default target to build the project
build:
	@forge build

# Run tests
test:
	@forge test -vvv

test-coverage:
	@forge coverage summary

# Clean build directory
clean:
	@rm -rf $(BUILD_DIR)

# Deploy contract (replace with your contract name and constructor args)
deploy-traffic-light:
	@forge create  --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --etherscan-api-key ${API_KEY} --broadcast src/TrafficLightZkOTP.sol:TrafficLightZkOTP --constructor-args-path constructor.txt --verify

# Deploy contract (replace with your contract name and constructor args)
deploy-verifier:
	@forge create  --rpc-url ${RPC_URL} --private-key ${PRIVATE_KEY} --etherscan-api-key ${API_KEY} --broadcast src/Groth16Verifier.sol:Groth16Verifier --verify

# Lint the code using solhint (if installed)
lint:
	@solhint $(SRC_DIR)/*.sol

# Format Solidity code using forge fmt
format:
	@forge fmt

# Default task if no target is provided
all: build test