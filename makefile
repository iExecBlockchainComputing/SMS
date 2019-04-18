.PHONY: all

all: buildImage

deps:
	yarn || npm i

buildImage: deps python/daemon.py
	docker image build -t iexechub/sms .

buildBin: deps python/daemon.py
	pyinstaller $< --onefile \
		--distpath ./bin \
		--workpath ./compile/build \
		--specpath ./compile \
		--hiddenimport packaging.specifiers \
		--hiddenimport packaging.requirements

clean:
	rm -rf ./compile

clear: clean
	rm -rf ./dist
