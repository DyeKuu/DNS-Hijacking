# A sample Makefile
# This Makefile demonstrates and explains 
# Make Macros, Macro Expansions,
# Rules, Targets, Dependencies, Commands, Goals
# Artificial Targets, Pattern Rule, Dependency Rule.

# Comments start with a # and go to the end of the line.

# Here is a simple Make Macro.

LINK_TARGET = dns_client dns_server

# Here is a Make Macro that uses the backslash to extend to multiple lines.
# This allows quick modification of more object files.

OBJS = \
	dns_client.o dns.o dns_server.o
	
# Here is a Make Macro defined by two Macro Expansions.
# A Macro Expansion may be treated as a textual replacement of the Make Macro.
# Macro Expansions are introduced with $ and enclosed in (parentheses).

REBUILDABLES = $(OBJS) $(LINK_TARGET)

# There are two standard Targets your Makefile should probably have:
# "all" and "clean", because they are often command-line Goals.
# Also, these are both typically Artificial Targets, because they don't typically
# correspond to real files named "all" or "clean".  

# The rule for "all" is used to incrementally build your system.
# It does this by expressing a dependency on the results of that system,
# which in turn have their own rules and dependencies.
all : $(LINK_TARGET)

# Make Macros do not need to be defined before their Macro Expansions,
# but they normally should be defined before they appear in any Rules.
# Consequently Make Macros often appear first in a Makefile.

# Here is a simple Rule (used for "cleaning" your build environment).
# It has a Target named "clean" (left of the colon ":" on the first line),
# no Dependencies (right of the colon),
# and two Commands (indented by tabs on the lines that follow).
# The space before the colon is not required but added here for clarity.

clean: 
	rm -f $(REBUILDABLES)

# There is no required order to the list of rules as they appear in the Makefile.
# Make will build its own dependency tree and only execute each rule only once
# its dependencies' rules have been executed successfully.

# Here is a Rule that uses some built-in Make Macros in its command:
# $@ expands to the rule's target
# $^ expands to the rule's dependencies
#$(LINK_TARGET) : $(OBJS)
#	cc -g3 -o $@ $^ 

dns_client : dns_client.o dns.o
	gcc -g3 -o $@ $^

dns_server : dns_server.o dns.o
	gcc -g3 -o $@ $^

# Here is a Pattern Rule, often used for compile-line.
# It says how to create a file with a .o suffix, given a file with a .c suffix.
# The rule's command uses some built-in Make Macros:
# $@ for the pattern-matched target
# $lt; for the pattern-matched dependency

%.o : %.c
	gcc -g3  -std=c99 -Wall -o $@ -c $<
  
# These are Dependency Rules, which are rules without any command.
# Dependency Rules indicate that if any file to the right of the colon changes,
# the target to the left of the colon should be considered out-of-date.
# The commands for making an out-of-date target up-to-date may be found elsewhere
# (in this case, by the Pattern Rule above).
# Dependency Rules are often used to capture header file dependencies.

dns_client.c: dns.h dns.c
dns_server.c: dns.h dns.c

 