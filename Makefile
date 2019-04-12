
CROSS_COMPILE=$(TOOLPREFIX)
OBJS=http.o json.o logs.o
CFLAGS+=-I$(TOPDIR)/apps/cmdlib/  -Wall -g
CC=$(CROSS_COMPILE)gcc


http.cgi:$(OBJS)
	@echo [LD] $@
	$(CROSS_COMPILE)gcc  -L$(TOPDIR)/apps/cmdlib/  -Wl,--gc-sections -o http.cgi $(OBJS)

%.o:%.c *.h
	@echo [CC] $<
	@$(CC) -c $(CFLAGS) $< -o $@ -ffunction-sections -fdata-sections


clean:
	rm *.o -rf
	rm http.cgi -rf

