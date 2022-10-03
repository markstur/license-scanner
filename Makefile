# SPDX-License-Identifier: Apache-2.0

SHELL:=/bin/bash

.PHONY: test
test: ## Run all the tests.
	@echo =============================
	@echo ==== Running Unit Tests =====
	@echo =============================
	go test ./... -tags=unit -count=1

.PHONY: cover
cover: ## Run the code coverage
	@echo ================================
	@echo ==== Running Code Coverage =====
	@echo ================================
	go test ./... -tags=unit -cover

.PHONY: cover-report
cover-report: ## Generate the code coverage HTML report
	@echo ==========================================
	@echo ==== Generating Code Coverage Report =====
	@echo ==========================================
	go test ./... -tags=unit -coverprofile=coverage.out # coverage.out is the output filename
	go tool cover -html=coverage.out