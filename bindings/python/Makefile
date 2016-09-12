# Python binding for Unicorn engine. Nguyen Anh Quynh <aquynh@gmail.com>

.PHONY: gen_const install install3 clean sdist sdist3 bdist bdist3 sdist_win bdist_win

gen_const:
	cd .. && python const_generator.py python

install:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	if test -n "${DESTDIR}"; then \
		python setup.py install --root="${DESTDIR}"; \
	else \
		python setup.py install; \
	fi

install3:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	if test -n "${DESTDIR}"; then \
		python3 setup.py install --root="${DESTDIR}"; \
	else \
		python3 setup.py install; \
	fi

# build & upload PyPi package with source code of the core
sdist:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	python setup.py sdist register upload

# build & upload PyPi package with source code of the core
sdist3:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	python3 setup.py sdist register upload

# build & upload PyPi package with precompiled core
bdist:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	python setup.py bdist_wheel register upload

# build & upload PyPi package with precompiled core
bdist3:
	rm -rf src/ dist/
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	python3 setup.py bdist_wheel register upload

# build & upload PyPi package with prebuilt core
# NOTE: be sure to have precompiled core under prebuilt/win*/ beforehand
sdist_win:
	rm -rf src/ dist/
	python setup.py sdist register upload

# build & upload PyPi package with prebuilt core
# NOTE: be sure to have precompiled core under prebuilt/win*/ beforehand
sdist3_win:
	rm -rf src/ dist/
	python3 setup.py sdist register upload

clean:
	rm -rf src/ dist/ build/ MANIFEST
	rm -rf prebuilt/win64/unicorn.dll
	rm -rf prebuilt/win32/unicorn.dll
	rm -rf unicorn/lib unicorn/include
	rm -rf unicorn/*.pyc
	rm -rf unicorn.egg-info


SAMPLES = sample_arm.py sample_arm64.py sample_mips.py
SAMPLES += sample_sparc.py sample_m68k.py sample_x86.py
check:
	@for t in $(SAMPLES); do \
		echo Check $$t ... ; \
		./$$t > /dev/null && echo OK || echo FAILED; \
	done

