all: build publish

OS=linux-x64 #win-x64, osx-x64
ARG=-c Release -f net6.0

clean:
	dotnet clean $(ARG)
	rm -rf bin
	rm -rf obj
	rm -f ipk-sniffer
	rm -f ipk-sniffer.pdb

build: 
	dotnet build $(ARG)

publish:
	dotnet publish -o . $(ARG) -r $(OS)
