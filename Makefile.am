AUTOMAKE_OPTIONS = foreign
SUBDIRS = mtcp/src apps/example apps/epproxy #io_engine/lib

install-man:
	@echo -e "\e[1;34mPlacing the man pages in the $(prefix)/man/man3/ directory $<\e[0m"
	@ mkdir -p $(prefix)/man/
	@ mkdir -p $(prefix)/man/man3/
	@ cp docs/man/* $(prefix)/man/man3/
	@echo -e "\e[1;34mUpdating man pages cache $<\e[0m"
	@ mandb > /dev/null 2> /dev/null

uninstall:
	@echo -e "\e[1;34mCleaning up... $<\e[0m"
	@ rm -rf $(prefix)/mtcp
	@ rm -rf $(prefix)/man/man3/mtcp_*
	@echo -e "\e[1;34mUpdating man pages cache $<\e[0m"
	@ mandb > /dev/null 2> /dev/null

if DPDK
install: all install-man
	@echo -e "\e[1;34mPlacing the libraries in the $(prefix)/mtcp/lib directory $<\e[0m"
	@ mkdir -p $(prefix)/mtcp/
	@ mkdir -p $(prefix)/mtcp/lib
	@ mkdir -p $(prefix)/mtcp/bin
	@ mkdir -p $(prefix)/mtcp/include
	@ cp mtcp/lib/libmtcp.a $(prefix)/mtcp/lib/
	@ cp dpdk/lib/* $(prefix)/mtcp/lib/
	@ cp -rL dpdk/include/* $(prefix)/mtcp/include/
	@ cp mtcp/include/* $(prefix)/mtcp/include/
	@echo -e "\e[1;34mPlacing the binaries in the $(prefix)/mtcp/bin directory $<\e[0m"
	@ cp `find apps/example/ -type f -executable -perm /a+x` $(prefix)/mtcp/bin/
else
install: all install-man
	@echo -e "\e[1;34mPlacing the libraries in the $(prefix)/mtcp/lib directory $<\e[0m"
	@ mkdir -p $(prefix)/mtcp/
	@ mkdir -p $(prefix)/mtcp/lib
	@ mkdir -p $(prefix)/mtcp/bin
	@ mkdir -p $(prefix)/mtcp/include
	@ cp mtcp/lib/libmtcp.a $(prefix)/mtcp/lib/
	@ cp mtcp/include/* $(prefix)/mtcp/include/
	@echo -e "\e[1;34mPlacing the binaries in the $(prefix)/mtcp/bin directory $<\e[0m"
	@ cp `find apps/example/ -type f -executable -perm /a+x` $(prefix)/mtcp/bin/
endif
