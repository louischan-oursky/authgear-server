.PHONY: check-tidy
check-tidy:
	test -z "$(shell git status --porcelain)"

.PHONY: fmt
fmt:
	npm run eslint:format
	npm run stylelint:format
	npm run prettier:format

.PHONY: lint
lint:
	npm run eslint
	npm run stylelint
	npm run prettier
	npm run typecheck
