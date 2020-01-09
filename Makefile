CLI = .build/${spec}

all: $(CLI)

$(CLI): .build
	make -C $(dir $@)

.build:
	mkdir -p $@
	cd $@ && CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig cmake ../circuit/${spec}/ || rm -rf ../$@

debug:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Debug ../circuit/${spec}

release:
	mkdir -p .build && cd .build && cmake -DCMAKE_BUILD_TYPE=Release ../circuit/${spec}

git-submodules:
	git submodule update --init --recursive

clean:
	rm -rf .build

run:$(CLI)
	time $(CLI)