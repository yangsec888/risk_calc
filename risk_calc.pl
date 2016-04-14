#!/usr/bin/perl
########################################################################
# Functional Description:
#
# "risk_calc.pl" is a customized program to calculate the risk score for
# firewall ACL. High risk ACL will be flagged and printed out.
# 	Currently support Cisco firewall: FWSM,ASA,PIX
#
########################################################################
# Usage Example:
#
#	$ ./risk_calc.pl -l <file with path of Firewall configs in each line>
########################################################################
# Developed by:		Yang Li, (917)667-1972
#
# Change History:
# Last modification: 	04/14/2016
# Version 		1.1a
#
#	04/14/2014	Update the parser to accomodate ASA 9.2(4) new syntax:
#									fqdn, subnet, object-group, object-network etc..
#	07/09/2012	Bug fix for incorrect cosolidation and loose rule entries under the
#			"-list" option, when there are duplicate firewall files under the list.
#	06/20/2012	Add support for searching firewall for unused object-group object(s),
#			via "-clean" command switch
#	06/19/2012	Add support for searching firewall for unused access-group object(s),
#			via "-clean" command switch
#	06/18/2012	Add support for sorting out loose rules, via '-loose' command
#			switch.
#	06/17/2012	Bug fix - add risk score calculation for trusted source IPs
#			also, per Kroum Ionov's suggestion.
#	06/12/2012	Implement report saving, via "-output" command switch
#	06/11/2012	Implement support for firewall ACL consolidation report,
#			via "-consolidate" command switch
#	06/10/2012	Additional face-lift; change the findings data structure to avoid garbled
#			printing; implement the "-acl" command switch
#	06/09/2012	Bug fix - same access group applied to different interfaces that may
#			cause miscount
#	06/09/2012	Add the ascii art banner, in addition to refactor the code.
#	05/30/2012	Minor code refactoring - add program verbose mode for easy debugging
#	11/14/2010	Minor bug fix. Support of "-file" command switch.
#	01/14/2010	Implement configuratin file ("-config" command switch)
#	12/09/2009	Support clean findings print-out at end
#	12/08/2009	Numerous bug fixes and support object name lookup
#	12/06/2009	Many bug fixes including support of deep inspection of object-group
#	12/04/2009	Numerous bug fixes to the stage of first working code
#	12/03/2009	Basic I/O design and framework development
########################################################################
## Program Modules Loading & Argument Check
########################################################################
# Load the extended Perl modules/libraries
use Getopt::Long qw/:config bundling_override no_ignore_case/;
use Net::CIDR;
use Socket;
########################################################################
# Program command argument check
########################################################################
my %opts;
my $ver="1.1a";
my $author="Yang Li (917)667-1972";
my $verbose=0;						# Debugging bit
GetOptions(
	\%opts,
	'help|h|?' => sub { &print_help and exit; },    # print help
	'list|l:s',                  			# Firewall configuration list for batch audit - each line with full path to file
	'file|f:s',                  	 		# Firewall configuration file - for example, "/home/john/runningAdmin.txt"
 	'acl|a:s',                  	 		# Quoted access control list - for example, "access-list 101 permit ip any any"
	'consolidate|s:s',				# Consolidation suggestions - for example, by grouping the destination services together
	'loose|u:s',					# Audit for loose rules, for example, flag the ACL when either the source, destination or service is "any"
	'clean|n:s',					# Audit for un-used object, rule, flag them out for clean up effort
	'config|c:s',                  	 		# risk_calc.pl configuration file
	'output|o:s',               			# Optional, program output file
	'version|v' => sub { &print_banner; exit;},	# Print version information
	'verbose+' => \$verbose,			# Optional, program verbose mode for debugging
	'vv+' => \$verbose,				# Optional, same as "-verbose", abbreviation "-vv"
);
# Command Arguments Capturing
my $list_firewalls=$opts{list};				# Firewall config file list
my $file_firewall=$opts{file};				# Single firewall config file
my $acl=$opts{acl};					# Firewall acl entry
my $consolidation_level=$opts{consolidate};		# Firewall acl consolidation level
my $loose_rule=$opts{loose};				# Firewall loose rules
my $clean=$opts{clean};					# Firewall clean up
my $file_config=defined $opts{config} ? $opts{config}
	: "./risk_calc.conf";				# default configuration - risk_calc.conf
unless ($list_firewalls || $file_firewall || $acl || $consolidation_level || $loose_rule || $clean) {
	&print_help;
	exit(1);
}							# Input sanity check
################################################################################
# 													Main Program
################################################################################
# Print the program banner
&print_banner;
our @ACL_YL, @ACL_RED, %CNF, %CONSOLIDATE, %LOOSE_RULE, %UNUSED;
my $cnt_acls_total=0, $cnt_fws=0, $cnt_yl=0, $cnt_red=0;
# Read Program Configuration File
&read_config_simple($file_config);
# Start working on various audit task
if (defined $opts{consolidate} || defined $opts{loose}) {		# Perform loose rule audit, or consolidation report
	if (defined $consolidation_level && $consolidation_level !~ /(1|2|3)/ ) {
		die "Program Input Error: Only level number 1,2,3 are accepted for the '-consolidate' option. Please read the program README.txt again!\n";
	} elsif (defined $loose_rule && $loose_rule !~ /(source|destination|service)/i ) {
		die "Program Input Error: Only 'source', 'destination', or 'service' are accepted for the '-loose_rule' option. Please read the program README.txt again!\n";
	}
	if (defined $consolidation_level) {
		print "\nExam the firewall ACL entries for potential consolidation opportunities ...\n";
	} elsif (defined $loose_rule) {
		print "\nExam the firewall ACL entries for ", $loose_rule, " loose rule ...\n";
	}
	if ($file_firewall) {
		my $cnt_acls=parse_fw($file_firewall);
		$cnt_acls_total+=$cnt_acls;
		$cnt_fws=1;
	} elsif ($list_firewalls) {
		open (IN0, $list_firewalls) || die "Can't open file $list_firewalls: $!\n";
		while (<IN0>) {
			chomp;
			my $file_firewall=$_;
			# Count the total number of acls processed
			my $cnt_acls=parse_fw($file_firewall);
			$cnt_acls_total+=$cnt_acls;
			$cnt_fws++;
		}
		close (IN0);
	} else {
		die "Program Input Error: you need to use either the '-file' or the '-list' option. Please read the program README.txt again!\n";
	}
	if (defined $consolidation_level) {
		&print_consolidation_report($consolidation_level);
	} elsif (defined $loose_rule) {
		print_loose_rule_report($loose_rule);
	}
} elsif ( defined $opts{clean} ) {							# Perform unused object audit
	if ($clean !~ /(object-group|access-group)/ ) {
		die "Program Input Error: Only 'object-group' or 'access-group' is accepted for the '-clean' option. Please read the program README.txt again!\n";
	}
	search_unused_object($opts{clean});
	print_unused_object($opts{clean});
} else {										# Perform risk score audit
	print "\nAudit the firewall ACL entries for the violation of the risk score standards ...\n";
	if ($acl) {
		print "Processing ACL entry: $acl", "\n";
		my ($score_total,$breakdown)=parse_access_list('undef','undef','undef',$acl);
		print "ACL Risk Score: ", $score_total, "\n", "Score breakdown (src,des,port): ", $breakdown, "\n";
		exit;
	} elsif ($list_firewalls) {
		open (IN9, $list_firewalls) || die "Can't open file $list_firewalls: $!\n";
		while (<IN9>) {
			chomp;
			my $confile_firewall=$_;
			# Count the total number of acls processed
			my $cnt_acls=parse_fw($confile_firewall);
			$cnt_acls_total+=$cnt_acls;
			$cnt_fws++;
		}
		close (IN9);
	} elsif ($file_firewall) {
		my $cnt_acls=parse_fw($file_firewall);
		$cnt_acls_total+=$cnt_acls;
		$cnt_fws=1;
	} else {
		&print_help and exit(1);
	}
	# Print the program output
	&print_findings;
}
exit(0);

########################################################################
# Functions & Subroutines
########################################################################
sub print_help () {
  #
  # print help inforamtion for the users
  #
        my $ph = (split /[\\|\/]/, $0)[-1];
		&print_banner;
        print <<HELP;
Functional Description:
	"risk_calc.pl" is a customized program to calculate the risk score for
	the Cisco firewalls. High risk ACL will be flagged out at the end of audit.
	Currently support the Cisco firewalls: FWSM,ASA,PIX

	Most helpful of this program would be the case, where you have a large
	number of firewall ACL entries. Since the manual calculation would be
	a time-consuming alternative.

Syntax:
        \$ $ph ?|-h|--help
								-h|?|help		Print help message
								-l|list			Firewall configuration list for batch audit - each line with full path to file
								-f|file			Firewall configuration file - for example, "/home/john/runningAdmin.txt"
								-a|acl			Quoted access control list - for example, "access-list 101 permit ip any any"
								-u|loose		Identify loose firewall rule by 'source', 'destination', or 'service'
								-s|consolidate		ACL Consolidation report level 1-3
                -c|config		Program configuration - default to "./risk_calc.conf"
								-o|output		Optional, program output file
								-v|version	Program version.
								-vv|verbose	Program debugging mode.

Usage Example:
	Example 1, to perform a mass audit on a list of firewalls:
		\$ echo "/home/yang/clientA/runningAdmin.txt" > ./list_fw_confs
		\$ echo "/home/yang/clientA/runningAdmin.txt" >> ./list_fw_confs
		...
		\$ $ph -list ./list_fw_confs -c /home/yang/Risk_Calc/risk_calc.conf

	Example 2, to perform audit on one firewall configuration file:
		\$ $ph -file /home/yang/clientA/runningAdmin.txt -c /home/yang/Risk_Calc/risk_calc.conf

	Example 3, to perform audit on one ACL entry from the command line:
		\$ $ph -acl "access-list outside_in extended permit ip any any eq www" -c /home/yang/Risk_Calc/risk_calc.conf

	Example 4, to print out firewall ACL consolidation level 1 report:
		\$ $ph -consolidate 1 -f /home/yang/clientA/runningAdmin.txt -c /home/yang/Risk_Calc/risk_calc.conf

	Example 5, to print out firewall loose rule by source report:
		\$ $ph -loose source -f /home/yang/clientA/runningAdmin.txt -c /home/yang/Risk_Calc/risk_calc.conf

	Example 6, to print out firewall unused rule report for firewall cleanup:
		\$ $ph -clean access-group -f /home/yang/clientA/runningAdmin.txt -c /home/yang/Risk_Calc/risk_calc.conf
HELP
}

sub read_config_simple () {
  #
  ## Read the program configuration file, store setting into hash %CNF
  #
	print "Reading program configuration file: $file_config\n";
	open (CONFIG, $_[0]) || die "Problem reading program configuration file $_[0]: $! \nPlease read the program README.txt file again.\n";
	while (my $line=<CONFIG>) {
		chomp($line);
		$line =~ s/\s+//g;
		#print "line: $line\n";
		if ($line =~ /^#/) {
			next;
		} elsif ($line =~ /^(.*)=(.*)/) {
			$CNF{$1} = $2;
		} else {
			next;
		}
	}
	close (CONFIG);
	print "Done!\n";
	if ($verbose) {
		print "Program configuration data: \n";
		foreach my $key (sort keys %CNF) { print "key: $key, val: $CNF{$key}\n";}
	}
}

sub search_unused_object () {
  #
  ## Search the firewall configuration file for unused object(s): object-group, access-group etc.. Save the findings into a hash
  #
	print "\nSearch firewall for unused object. Unused object type: $_[0]\n\n";
	if ($_[0] eq "access-group") {
		if (defined $opts{file}) {
			$cnt_fws=1;
			my @active_access_group = active_access_group_lookup($opts{file});		# look for applied access-group(s) in the configuration file
			my @unused_rules = unused_rule_lookup(\@active_access_group,$opts{file});
			foreach (@unused_rules) {
				push @{$UNUSED{$opts{file}}{entry}}, $_;
			}
		} elsif (defined $opts{list}) {
			open (IN6, $opts{list}) || die "Can't open file $opts{list}: $!\n";
			while (<IN6>) {
				chomp;
				my $file_firewall=$_;
				$cnt_fws++;
				my @active_access_group=active_access_group_lookup ($file_firewall);	# look for applied access-group(s) in the configuration file
				my @unused_rules=unused_rule_lookup(\@active_access_group,$file_firewall);
				foreach (@unused_rules) {
					push @{$UNUSED{$file_firewall}{entry}}, $_;
				}
			}
			close (IN6);
		} else {
			die "Program Input Error: you need to use either the '-file' or the '-list' option. Please read the program README.txt again!\n";
		}
	} elsif ($_[0] eq "object-group") {
		if (defined $opts{file}) {
			$cnt_fws=1;
			my @defined_object_group = defined_object_group($opts{file});			# look for defined object-group(s) in the configuration file
			#foreach (@defined_object_group) { print $_,"\n"; }
			#exit;
			my @unused_object = unused_object_lookup(\@defined_object_group,$opts{file});
			foreach (@unused_object) {
				push @{$UNUSED{$opts{file}}{entry}}, $_;
			}
		} elsif (defined $opts{list}) {
			open (IN7, $opts{list}) || die "Can't open file 6 - $opts{list}: $!\n";
			while (<IN7>) {
				chomp;
				my $file_firewall=$_;
				$cnt_fws++;
				my @defined_object_group = defined_object_group($file_firewall);	# look for defined object-group(s) in the configuration file
				my @unused_object = unused_object_lookup(\@defined_object_group,$file_firewall);
				foreach (@unused_object) {
					push @{$UNUSED{$file_firewall}{entry}}, $_;
				}
			}
			close (IN7);
		} else {
			die "Program Input Error: you need to use either the '-file' or the '-list' option. Please read the program README.txt again!\n";
		}
	} else {
		die "Program Input Error: only 'access-group' or 'object-group' is accepted for '-clean' option.\n";
	}
}

sub parse_fw () {
  #
  ## Calculate the total risk score on the firewall, including different non-inside access group(s)
  #
	my $cnt_fw_acls=0;
	my $conf=$_[0];
	print "\nProcessing Cisco firewall configuration file: $conf ...\n";
	my %AG; # access-group
	@access_group_entries=applied_access_group_entry ($conf);					# look for applied access-group(s) as starting point
	foreach (@access_group_entries) {
		chomp;
		@ag=split(/\s+/,$_);
		$AG{$ag[4]}=$ag[1];									# interface => ag_name hea
	}
	foreach my $key (sort keys %AG) {
		if ($key !~ /inside/i) {								# ignore outbound ACL by default
			print "Protected interface: $key <= ACL Group: $AG{$key}\n";
			# pass fw config file name,  access group name, and interface name; return # acls in access group
			my $count = parse_access_group($conf,$AG{$key}, $key);
			$cnt_fw_acls+=$count;
		}
	}
	print "Total ACLs audited in $conf: $cnt_fw_acls \n";
	print "Done!\n";
	return $cnt_fw_acls;
}

sub applied_access_group_entry () {
  #
  ## Looking for lines such "access-group INSIDE-ACL in interface inside". i.e. the access group(s) that's applied to the firewall interfaces
  ## Return the whole line(s) for further processing
  #
	my @ag;
	open (IN10, $_[0]);
	while (<IN10>) {
		if (/^access-group\s.*in\sinterface/){
			chomp;
			push (@ag,$_);
		}
	}
	close (IN10);
	return @ag;
}

sub active_access_group_lookup () {
  #
  ## Looking for lines such "access-group INSIDE-ACL in interface inside"; extract the access group name(s)
  ## Return the access group name(s)
  #
	my @ag;
	open (IN4, $_[0]);
	while (<IN4>) {
		if (/^access-group\s.*in\sinterface/){
			my @access = split(/\s/, $_);
			push @ag,$access[1];
		} elsif (/^nat\s(.)*access-list\s(.)*/) {
			my @nat= split(/\s/,$_);
			#die "Access group in the NAT rule: $nat[4]\n";
			push @ag,$nat[4];
		}
	}
	close (IN4);
	return @ag;
}

sub unused_rule_lookup () {
  #
  ## Looking for access-list that not being used
  #
	print "\nChecking firewall $_[1] for unused rule ...\n";
	my @ACL;
	open (IN5, $_[1]) || die "Can't open file 5: $!\n";
	while (<IN5>) {
		chomp;
		if (/^access-list\s.*(permit|deny)/){
			my $found=0;
			my $acl=$_;
			my @access_list = split(/\s/, $acl);
			my $ag=$access_list[1];
			foreach(@{$_[0]}) {
				#print "Checking $ag against active access-group: $_\n";
				if ( $_ eq $ag) {
					$found++;
					break;
				}
			}
			unless ($found) {
				#print "Unused rule found: $acl\n";
				push @ACL, $acl;
			}
		}
	}
	close (IN5);
	print "Done!\n";
	return @ACL;
}

sub defined_object_group () {
  #
  ## Looking for a list of defined object group
  #
	print "Searching $_[0] for defined object group(s) ...\n";
	my @OG;
	open (IN7,$_[0]) || die "Can't open file 7: $!\n";
	while (<IN7>) {
		if (/^object-group\s/) {
			push @OG, $_;
		}
	}
	close(IN7);
	print "Done!\n";
	return @OG;
}

sub unused_object_lookup () {
  #
  ## Looking for object-group that not being used
  #
	print "Checking firewall $_[1] for unused object-group ...\n";
	my @UNUSED_OBJ;
	foreach(@{$_[0]}) {
		my $cur_obj=$_;
		my @obj=split(/\s/,$_);
		my $obj_name=$obj[2];
		my $found=0;
		open (IN8, $_[1]) || die "Can't open file 8: $!\n";
		while (<IN8>) {
			if (/^access-list\s.*(permit|deny)/){
				my @acl=split(/\s/,$_);
				foreach(@acl) {
					#print "Checking $ag against active access-group: $_\n";
					if ( $_ eq $obj_name) {
						$found++;
						break;
					}
				}
			}
			break if ($found);
		}
		close (IN8);
		unless ($found) {
			push @UNUSED_OBJ, $cur_obj;
		}
	}
	print "Done!\n";
	return @UNUSED_OBJ;
}

sub parse_access_group () {
  #
  ## Parse the access-group in use and return the ACL count
  #
	my $count=0;
	@acls=access_list_lookup($_[0], $_[1]);
	foreach (@acls) {
		chomp;
		$count++;
		my $cur_acl=$_;
		# Pass the firewall configuration file, access group, applied interface, and the ACL entry
		parse_access_list($_[0],$_[1], $_[2], $cur_acl);
	}
	print "Total ACLs audited in ACL group $_[1]: $count\n";
	return $count;
}

sub access_list_lookup () {
  #
  ## Lookup ACL under a specific access-group
  #
	my @ACLS;
	open (IN1, $_[0]);
	while (<IN1>) {
		if (/^access-list $_[1] (|extended )permit/g) {
			push(@ACLS,$_);
		}
	}
	close(IN1);
	return @ACLS;
}

sub parse_access_list() {
  #
  ## parse the ACL entry; depending on the command switch, it may perform different tasks during the parsing;
  ## For example, it may calculate the risk score for the ACL entry and store the information if it's a finding
  #
	my $non_trusted_addr=0;
	# Step 1 - Preparing
	chomp;
	my $current_acl_entry=$_[3];						# save a copy of the original 'ACL'
	if ($verbose) { print "\nProcessing line: $_[3]\n"; }
	$current_acl_entry=~s/\slog.*$//g;					# get rid of postfix log option portion of ACL
	$current_acl_entry=~s/access-list (.)* (|extended )permit\s+//g;	# get rid of prefix "access-list xxx [extended] permit"
	if ($verbose) { print "ACL Compact Format: $current_acl_entry", "\n"; }	# debugging checkpoint start here
	my @ACL=split(/\s+/, $current_acl_entry);
	# Step 2 - Retrieve the ACL elements from ACL
	my $proc; my $src_ip; my $src_mask; my $src_port; my @src_blk;
	my $des_ip; my $des_mask; my @des_blk; my $des_port; my @des_ports;
	######protocol####
	$proc= shift (@ACL);							# identify protocol first: (ip|tcp|udp)
	if ($proc !~ /(ip|tcp|udp)/i) { next;}					# skip icmp etc...
	######src ip#####							# identify source IP
	if ($ACL[0] eq "any") {
		$src_ip = shift(@ACL);
		$src_mask = "0.0.0.0";
	} elsif ($ACL[0] eq "host") {
		shift(@ACL);
		if ($ACL[0] =~ /\d+\.\d+\.\d+\.\d+/) {
			$src_ip = shift(@ACL);
		} else {
			my $src_name=shift(@ACL);
			$src_ip = object_name_lookup($src_name,$_[0]);
		}
		$src_mask = "255.255.255.255";
	} elsif ($ACL[0] =~ /\d+\.\d+\.\d+\.\d+/) {
		$src_ip = shift(@ACL);
		$src_mask=shift(@ACL);
	} elsif ($ACL[0] =~ /(object-group|object)/) {
		shift(@ACL);
		my $obj_name=shift(@ACL);
		$src_ip = $obj_name;
		@src_blk=object_group_lookup($obj_name,$_[0]);
		if ($verbose) { print "obj_name: $obj_name, search in: $_[0], srcblk len: $#src_blk\n"; }
	} elsif ($ACL[0] !~ /\d+\.\d+\.\d+\.\d+/i) {
		my $src_name=shift(@ACL);
		$src_ip = object_name_lookup($src_name,$_[0]);
		$src_mask = shift(@ACL);
	} else {
		die "Warming! Problem in firewall $_[0] - parsing: $acl: unknown source IP format: $ACL[0]\n";
	}
	######src port#####							# identify source port
	if ($ACL[0] eq "eq") {
		shift(@ACL);
		$src_port=shift(@ACL);
	} elsif ($ACL[0] eq "range") {
		shift (@ACL);
		$src_port=shift(@ACL);
		$src_port = $src_port . "-" . shift(@ACL);
	} elsif ($ACL[0] eq "gt") {
		shift (@ACL);
		$src_port=shift(@ACL);
		$src_port = $src_port . "-65535";
	} else {
		$src_port="any";
	}
	#####dest ip#####							# identify destination IP
	if ($ACL[0] eq "any") {
		$des_ip = shift(@ACL);
		$des_mask = "0.0.0.0";
	} elsif ($ACL[0] eq "host") {
		shift(@ACL);
		if ($ACL[0] =~ /\d+\.\d+\.\d+\.\d+/i) {
			$des_ip = shift(@ACL);
		} else {
			my $des_name=shift(@ACL);
			$des_ip = object_name_lookup($des_name,$_[0]);
		}
		$des_mask = "255.255.255.255";
	} elsif ($ACL[0] =~ /\d+\.\d+\.\d+\.\d+/) {
		$des_ip = shift(@ACL);
		$des_mask=shift(@ACL);
	} elsif ($ACL[0] =~ /(object-group|object)/) {
		shift(@ACL);
		my $obj_name=shift(@ACL);
		$des_ip=$obj_name;
		@des_blk=object_group_lookup($obj_name,$_[0]);
	} elsif ($ACL[0] !~ /\d+\.\d+\.\d+\.\d+/i) {
		my $des_name=shift(@ACL);
		$des_ip = object_name_lookup($des_name,$_[0]);
		$des_mask = shift(@ACL);
	} else {
		die "Warming! Problem in firewall $_[0] - parsing $acl: unknown destination IP format: $ACL[0]\n";
	}
	#####dest port#####							# identify destination port
	if ($ACL[0] eq "") {
		$des_port="any";
	} elsif ($ACL[0] eq "eq") {
		shift (@ACL);
		$des_port=shift(@ACL);
	} elsif ($ACL[0] eq "range") {
		shift (@ACL);
		$des_port=shift(@ACL);
		$des_port = $des_port . "-" . shift(@ACL);
	} elsif ($ACL[0] eq "gt") {
		shift (@ACL);
		$des_port=shift(@ACL);
		$des_port = $des_port . "-65535";
	} elsif ($ACL[0] =~ /(object-group|object)/) {
		shift (@ACL);
		my $obj_name=shift(@ACL);
		$des_port=$obj_name;
		@des_ports=object_group_lookup($obj_name,$_[0]);
	} elsif ($ACL[0] eq "any") {
		$des_port=shift(@ACL);
	} else {
		die "Warming! Problem in firewall $_[0] - parsing $acl: unknown destination port format: $ACL[0]. proc: $proc src: $src_ip src_mask: $src_mask src_port $src_port des_ip: $des_ip des_mask:$des_mask \n";
	}
	# debugging checkpoint #2
	print "Re-assemble for debugging:\n", "proc;src_ip;src_mask;src_port;des_ip;des_mask;des_port:\n", "$proc;$src_ip;$src_mask;$src_port;$des_ip;$des_mask;$des_port\n" if $verbose;
	# Step 3 - Examine the ACL entries for potential consolidation opportunity
	if (defined $opts{consolidate}) {
		my $key;
		if ($consolidation_level eq 1) {
			$key=$_[0].";".$proc.";".$_[1].";".$src_ip.";".$src_mask.";".$src_port.";".$des_ip.";".$des_mask;
		} elsif ($consolidation_level eq 2) {
			$key=$_[0].";".$proc.";".$_[1].";".$src_port.";".$des_ip.";".$des_mask.";".$des_port;
		} elsif ($consolidation_level eq 3) {
			$key=$_[0].";".$proc.";".$_[1].";".$src_ip.";".$src_mask.";".$src_port.";".$des_port;
		} else {
			die "Error On Program Input: -consolidate level is from 1 to 3 only! \n";
		}
		$CONSOLIDATE{$consolidation_level}{$key}{count}=$CONSOLIDATE{$consolidation_level}{$key}{count}+1;
		push @{$CONSOLIDATE{$consolidation_level}{$key}{entries}},$_[3];
		$CONSOLIDATE{$consolidation_level}{$key}{firewall}=$_[0];
		#$CONSOLIDATE{$consolidation_level}{$key}{ag}=$_[1];
	}
	# Step 4 - Examine the ACL entries for the 'loose rule'; see 'README.txt' for the detail definitions
	if (defined $opts{loose}) {
		my $key;
		if ($loose_rule eq "source") {
			if ($src_ip eq "any") {
				$key=$_[0].";".$proc.";".$_[1].";".$des_ip.";".$des_mask.";".$des_port;
			} else {
				next;
			}
		} elsif ($loose_rule eq "destination") {
			if ($des_ip eq "any") {
				$key=$_[0].";".$proc.";".$_[1].";".$src_ip.";".$src_port.";".$des_port;
			} else {
				next;
			}
		} elsif ($loose_rule eq "service") {
			if ($des_port eq "any") {
				$key=$_[0].";".$proc.";".$_[1].";".$src_ip.";".$src_mask.";".$src_port.";".$des_port;
			} else {
				next;
			}
		} else {
			die "Error On Program Input: - 'loose_rule' is one of the following only: (source|destination|service)! \n";
		}
		$LOOSE_RULE{$loose_rule}{$key}{count}=$LOOSE_RULE{$loose_rule}{$key}{count}+1;
		push @{$LOOSE_RULE{$loose_rule}{$key}{entries}},$_[3];
		$LOOSE_RULE{$loose_rule}{$key}{firewall}=$_[0];
		$LOOSE_RULE{$loose_rule}{$key}{interface}=$_[2];
	}
	#Step 5 - Perform risk score calculation for the ACL entry
	unless (defined $opts{consolidate} || defined $opts{loose}) {
		my $score_src_ip=0, $score_des_ip=0, $score_des_port=0, $score_total=0;
		my $src_blk_min_bit=32, $des_blk_min_bit=32;
		my @BLK_TRUSTED=split(/,/,$CNF{BLK_TRUSTED});
		###### src ip score calculation#####
		# determine if this is an trusted source IP or not
		if ( ($src_ip =~ /\d+\.\d+\.\d+\.\d+/) && ($src_mask =~ /\d+\.\d+\.\d+\.\d+/) ) {
			my $cidr_src=Net::CIDR::addrandmask2cidr($src_ip,$src_mask);
			if (!Net::CIDR::cidrlookup($cidr_src, @BLK_TRUSTED)) { $non_trusted_addr++; }
		} elsif ($#src_blk>=0) {
			foreach (@src_blk) {
				if ( /\d+\.\d+\.\d+\.\d+\/\d+/) {
					my $blk=$_;
					if (!Net::CIDR::cidrlookup($blk, @BLK_TRUSTED)) {
						$non_trusted_addr++;
						my @BL=split(/\//,$blk);
						if ($BL[1] < $src_blk_min_bit) {
							$src_blk_min_bit=$BL[1];
						}
					}
				}
			}
		} elsif ($src_ip eq "any") {
			$non_trusted_addr=1;
		} else {
			die "Problem retrieve source IP elements - src_ip: $src_ip, src_mask: $src_mask, src_blk: $#src_blk\n";
		}
		###Starting the calculation for non-trusted source IP address
		if ($non_trusted_addr) {
			if ($src_ip eq "any") {
				$score_src_ip=40;
			} elsif ( ($src_ip =~ /\d+\.\d+\.\d+\.\d+/) && ($src_mask =~ /\d+\.\d+\.\d+\.\d+/) ) {
				my $blk=Net::CIDR::addrandmask2cidr($src_ip,$src_mask);
				my @BLK=split(/\//,$blk);
				my $bit=$BLK[1];
				if ($bit==32) {
					$score_src_ip=0;
				} elsif (($bit<32)&&($bit>24)) {
					$score_src_ip=0;
				} elsif (($bit<=24) && ($bit>20)) {
					$score_src_ip=15;
				} elsif (($bit<=20) && ($bit>16)) {
					$score_src_ip=25;
				} elsif ($bit<=16) {
					$score_src_ip=35;
				}
			} elsif ($#src_blk>=0) {
				my $bit=$src_blk_min_bit; 	# from previous calculation
				if ($bit==32) {
					$score_src_ip=0;
				} elsif (($bit<32)&&($bit>24)) {
					$score_src_ip=0;
				} elsif (($bit<=24) && ($bit>20)) {
					$score_src_ip=15;
				} elsif (($bit<=20) && ($bit>16)) {
					$score_src_ip=25;
				} elsif ($bit<=16) {
					$score_src_ip=35;
				}
			} else {
				die "Problem processing src score - src_ip: $src_ip, src_mask: $src_mask, src_blk: @src_blk\n";
			}
		} else {
			#next;											# Skip for trust source IP(s)
			$score_src_ip=0;									# no penalty for trust IP(s)
		}
		###### dest ip score calculation#####
		##Calculate the smallest netmask bit if it's an access-group
		if ($#des_blk>=0) {
			foreach (@des_blk) {
				if ( /\d+\.\d+\.\d+\.\d+\/\d+/) {
					my $blk=$_;
					my @BL=split(/\//,$blk);
					if ($BL[1] < $des_blk_min_bit) {
						$des_blk_min_bit=$BL[1];
					}
				}
			}
		}
		##Calculate the score for dest IP space based on the netmask bits
		if ($des_ip eq "any") {
			$score_des_ip=80;
		} elsif ( ($des_ip =~ /\d+\.\d+\.\d+\.\d+/) && ($des_mask =~ /\d+\.\d+\.\d+\.\d+/) ) {
			my $blk=Net::CIDR::addrandmask2cidr($des_ip,$des_mask);
			my @BLK=split(/\//,$blk);
			my $bit=$BLK[1];
			if ($bit==32) {
				$score_des_ip=0;
			} elsif (($bit<32)&&($bit>24)) {
				$score_des_ip=0;
			} elsif (($bit<=24) && ($bit>20)) {
				$score_des_ip=30;
			} elsif (($bit<=20) && ($bit>16)) {
				$score_des_ip=50;
			} elsif ($bit<=16) {
				$score_des_ip=70;
			}
		} elsif ($#des_blk>=0) {
			my $bit=$des_blk_min_bit;								# from previous calculation
			if ($bit==32) {
				$score_des_ip=0;
			} elsif (($bit<32)&&($bit>24)) {
				$score_des_ip=0;
			} elsif (($bit<=24) && ($bit>20)) {
				$score_des_ip=30;
			} elsif (($bit<=20) && ($bit>16)) {
				$score_des_ip=50;
			} elsif ($bit<=16) {
				$score_des_ip=70;
			}
		} else {
			die "Problem retrive des IP info - des_ip: $des_ip, des_mask: $des_mask, des_blk: @des_blk\n";
		}
		###### dest port risk calculation#####
		if (($des_port eq "any")&&($proc eq "ip")) {
			$score_des_port=50;
		} elsif (($des_port eq "any")&&($proc =~ /(udp|tcp)/i)) {
			$score_des_port=30;
		} elsif ($des_port =~ /\d+\-\d+/) {
			my ($des_port_start, $des_port_end) = split (/\-/,$des_port);
			# more than 100 port range is consider 'excessive', refer to the configuration file for the setting
			if (($des_port_end - $des_port_start) > $CNF{excessive_port_range}) {
				$score_des_port=20;
			} elsif (is_risky_port($des_port_start)) {
				$score_des_port=20;
			} elsif (is_risky_port($des_port_end)){
				$score_des_port=20;
			} else {
				$score_des_port=0;
			}
		} elsif ($des_port) {
			if ($des_port =~ /\-/) {	#for port-rannge such as "ftp-telnet"
				my @LN=split(/\-/,$des_port);
				foreach(@LN) {
					if (is_risky_port($_)) { $score_des_port=20;}
				}
			} else {
				if (is_risky_port($des_port)) { $score_des_port=20;}
			}
		} elsif ($#des_ports>=1) {
			foreach(@des_ports) {
				if (is_risky_port($_)) { $score_des_port=20;}
			}
		} else {
			$score_des_port=0;
		}
		###### total risk calculation#####
		$score_total=$score_src_ip+$score_des_ip+$score_des_port;
		my $break_down= $score_src_ip." + ".$score_des_ip." + ".$score_des_port;
		# Flagging the ACL entry if meeting the threshold, and saving the info into the finding data structure
		if ($score_total >= $CNF{risk_yellow}) {
			print "Risky ACL Entry Found: $_[3]", "\n";
			print "Risk Score(src,des,port):  $score_src_ip + $score_des_ip + $score_des_port = $score_total \n";
			my $finding=$score_total.",".$break_down.",".$_[0].",".$_[2].",".$_[1].",".$_[3];		# finding entry detail
			if ($score_total < $CNF{risk_red}) {
				$cnt_yl++;
				# save result into global hash %ACL_YL
				push @ACL_YL, $finding;
			} else {
				# save result into global hash %ACL_RED
				$cnt_red++;
				push @ACL_RED, $finding;
			}
		}
		return ($score_total, $break_down);
	}
	return "undef";								# return undef for tasks other than risk score calculation
}

sub object_name_lookup () {
  #
  ## Lookup object name definition, return IP for name. For example, "name 10.68.68.0 Red_lab" will return "10.68.68.0"
  #
	my $IP;
	open (IN2,$_[1]) || die "Can't open file $_[1]: $!\n";
	while (<IN2>) {
		if (/^name\s+(\d+\.\d+\.\d+\.\d+)\s+$_[0]/g) {
			return $1;
		}
	}
	close(IN2);
	return "undef";
}

sub object_group_lookup () {
  #
  ## Perform object group lookup for ACL; use object group name as input, return
	##  the network blocks, service ports as an array accordingly
  #
	print "Perform object group lookup on: $_[0]\n" if $verbose;
	my $obj_gp_name=$_[0], $fw_conf=$_[1];
	my $obj_type; my $recording=0; my @BLOCKS; my @PORTS;
	open (IN3,$fw_conf) || die "Can't open file $_[1]: $!\n";
	while (<IN3>) {
		chomp;
		$line=$_;
		if (/^\s+/) {
		} else {
			$recording=0;						# Reset on next object-group block start
		}
		if ((/^(object-group|object)\s(service|network)\s/) && (/\s+$obj_gp_name\s+/)) {
			$recording++;
			if ($line =~ /^(object-group|object)\s(service|network)\s/gi) {
				$obj_type=$2;
				#print "Object type: $obj_type\n" if $verbose
			}
			next;
		}
		if ($recording && ($obj_type eq "network")) {
			if ($line =~ /^\s+(description|remark)/i) { next; }		# skip on "description xxxx", "access-list xxxx remark xxxx" lines
			$line=~s/^\s+//g;
			my @LINE=split(/\s+/,$line);
			#if ($verbose) {
			#	foreach (@LINE) { print $_, ","; } 
			#}
			if ($LINE[0] =~ /(group-object|network-object)/) {			# recursive function is used to process nested "group-object", "network-object"
				my @B=object_group_lookup($LINE[1],$fw_conf);
				push(@BLOCKS,@B);
			} elsif ($LINE[0] eq "host") {
				my $blk;
				if ($LINE[1] =~ /\d+\.\d+\.\d+\.\d+/){
					$blk=$LINE[1]."/32";
				} else {
					my $ip = &object_name_lookup($LINE[1],$_[1]);
					$blk=$ip."/32";
				}
				@BLOCKS=Net::CIDR::cidradd($blk,@BLOCKS);
			} elsif ($LINE[1] eq "fqdn") {
				my $blk;
				my $ip = inet_ntoa(inet_aton($LINE[2]));  # perform nslookup on fqdn by using Socket module function 'inet_ntoa'
				$blk=$ip."/32";
				@BLOCKS=Net::CIDR::cidradd($blk,@BLOCKS);
			} elsif ($LINE[1] eq "subnet") {
				my $blk=Net::CIDR::addrandmask2cidr($LINE[2],$LINE[3]);
				@BLOCKS=Net::CIDR::cidradd($blk,@BLOCKS);
			} elsif ( ($LINE[1] =~ /\d+\.\d+\.\d+\.\d+/) && ($LINE[2] =~ /\d+\.\d+\.\d+\.\d+/) ) {
				my $blk=Net::CIDR::addrandmask2cidr($LINE[1],$LINE[2]);
				@BLOCKS=Net::CIDR::cidradd($blk,@BLOCKS);
			} elsif ( ($LINE[1] !~ /\d+\.\d+\.\d+\.\d+/) && ($LINE[2] =~ /\d+\.\d+\.\d+\.\d+/) ) {
				my $ip = &object_name_lookup($LINE[1],$_[1]);
				my $blk=Net::CIDR::addrandmask2cidr($ip,$LINE[2]);
				@BLOCKS=Net::CIDR::cidradd($blk,@BLOCKS);
			} else {
				die "Problem processing 2: $line\n";
			}
		} elsif ($recording && ($obj_type eq "service")) {
			if ($line =~ /^\s+(description|remark)/i) { next; } 		# skip on "description xxxx", or "access-list Outside-In remark xxxx" lines
			my @LINE=split(/\s+/,$line);
			if ($LINE[2] eq "eq") {
				push (@PORTS,$LINE[3]);
			} elsif ( $LINE[2] eq "range" ){
				my $prt=$LINE[3]."-".$LINE[4];
				push (@PORTS,$prt);
			} elsif ($LINE[1] eq "group-object") {			# added to process nested "group-object"
				my @P=object_group_lookup($LINE[2],$fw_conf);
				push (@PORTS,@P);
			} else {
				die "Problem processing 1: $line\n";
			}
		} elsif ($recording && ($obj_type eq "icmp-type")) {
										# intentional skip on icmp types
		}
	}
	close(IN3);
	print "Object group lookup done.\n" if $verbose;
	if ($obj_type eq "network") {
		return @BLOCKS;
	} elsif ($obj_type eq "service") {
		return @PORTS;
	} else {
		return "undef";
	}
}

sub is_risky_port () {
  #
  ## Determine if the destination port is risky or not. For example: return "1" if port is "sqlnet"
  #
	my $risky=0;
	foreach (split(/,/,$CNF{risky_ports})) {
		if (/$_[0]/i) {
			$risky++;
			return $risky;
		}
	}
	return $risky;
}

sub print_findings {
  #
  ## Print out yellow and red risk finding table from global hash
  #
	if (defined $opts{output}) {
		print "\nSaving the audit report into file: ",$opts{output}, "\n...\n";
		open (OUT, ">", $opts{output}) || die " Can't open file for write access: $opts{output} : $!\n";
	}
	if (defined $opts{output}) {
		print OUT "\nRisk Score Audit Report Summary:\n";
		print OUT "Total ACLs audited in $cnt_fws firewall(s): $cnt_acls_total \n";
		print OUT "Total ACLs with risk score equal or greater than $CNF{risk_red} (Red Finding): $cnt_red \n";
		print OUT "Total ACLs with risk score between $CNF{risk_yellow}-$CNF{risk_red} (Yellow Finding): $cnt_yl \n";
	} else {
		print "\nRisk Score Audit Report Summary:\n";
		print "Total ACLs audited in $cnt_fws firewall(s): $cnt_acls_total \n";
		print "Total ACLs with risk score equal or greater than $CNF{risk_red} (Red Finding): $cnt_red \n";
		print "Total ACLs with risk score between $CNF{risk_yellow}-$CNF{risk_red} (Yellow Finding): $cnt_yl \n";
	}
	my $num_red=$#ACL_RED+1;
	my $num_yl=$#ACL_YL+1;
	if ($num_red>0) {
		if (defined $opts{output}) {
			print OUT "\nRisk Score Red Finding Table ($num_red Entries): \n";
			print OUT "ACL Risk Score,Score Breakdown,Firewall,Applied Interface,ACL Group,ACL Entry\n";
		} else {
			print "\nRisk Score Red Finding Table ($num_red Entries): \n";
			print "ACL Risk Score,Score Breakdown,Firewall,Applied Interface,ACL Group,ACL Entry\n";
		}
		foreach (sort @ACL_RED) {
			if (defined $opts{output}) {
				print OUT "$_\n";
			} else {
				print $_, "\n";
			}
		}
	} else {
		if (defined $opts{output}) {
			print OUT "\nRisk Score Red Finding Table (No Entry!) \n";
		} else {
			print "\nRisk Score Red Finding Table (No Entry!) \n";
		}
	}
	if ($num_yl>0) {
		if (defined $opts{output}) {
			print OUT "\nRisk Score Yellow Finding Table ($num_yl Entries): \n";
			print OUT "ACL Risk Score,Score Breakdown,Firewall,Applied Interface,ACL Group,ACL Entry\n";
		} else {
			print "\nRisk Score Yellow Finding Table ($num_yl Entries): \n";
			print "ACL Risk Score,Score Breakdown,Firewall,Applied Interface,ACL Group,ACL Entry\n";
		}
		foreach (sort @ACL_YL) {
			if (defined $opts{output}) {
				print OUT $_, "\n";
			} else {
				print $_, "\n";
			}
		}
	} else {
		if (defined $opts{output}) {
			print OUT "\nRisk Score Yellow Finding Table (No Entry!) \n";
		} else {
			print "\nRisk Score Yellow Finding Table (No Entry!) \n";
		}
	}
	if (defined $opts{output}) {
		close(OUT);
		print "Done saving report!\n";
	}
}

sub print_consolidation_report () {
  #
  ## Print out potential ACL entry consolidation reports
  #
	my $count=0;
	my $cnt_eliminated=0;
	my %report_levels = (1, "Consolidation Based On Destination Service(s)",
           2, "Consolidation Based On Source IP Address(es)",
           3, "Consolidation Based on Destination Address(es)"
	);
	my $level=$_[0];
	if (defined $opts{output}) {
		print "\n\nSaving the consolidation report into file: ",$opts{output}, "\n...\n";
		open (OUT, ">", $opts{output}) || die " Can't open file for write access: $opts{output} : $!\n";
	}
	if (defined $opts{output}) {
		print OUT "\n\nFirewall ACL Consolidation Level $level Report\n";
		print OUT "Level ", $level, " - ", $report_levels{$level}, "\n";
		print OUT "Total ACLs audited in $cnt_fws firewall(s): $cnt_acls_total \n\n\n";
	} else {
		print "\n\nFirewall ACL Consolidation Level $level Report\n";
		print "Level ", $level, " - ", $report_levels{$level}, "\n";
		print "Total ACLs audited in $cnt_fws firewall(s): $cnt_acls_total \n\n\n";
	}
	foreach my $key (keys %{$CONSOLIDATE{$level}}) {
		if ($CONSOLIDATE{$level}{$key}{count}>1) {
			$count++;
			$cnt_eliminated=$cnt_eliminated+$CONSOLIDATE{$level}{$key}{count}-1;
			if (defined $opts{output}) {
				print OUT "ACL Consolidation Group ",$count," on Firewall: ", $CONSOLIDATE{$level}{$key}{firewall}, "\n";
				print OUT "Sub-total: ", $CONSOLIDATE{$level}{$key}{count}, " entries\n";
				my @entries= @{$CONSOLIDATE{$level}{$key}{entries}};
				foreach (@entries) {
					print OUT "$_\n";
				}
				print OUT "\n";
			} else {
				print "ACL Consolidation Group ",$count," on Firewall: $CONSOLIDATE{$level}{$key}{firewall}", "\n";
				print "Sub-total: ", $CONSOLIDATE{$level}{$key}{count}, " entries\n";
				my @entries= @{$CONSOLIDATE{$level}{$key}{entries}};
				foreach (@entries) {
					print "$_\n";
				}
				print "\n";
			}
		}
	}
	if (defined $opts{output}) {
		print OUT "\nYou can use the Cisco 'object group' feature to combine the ACL entries group by group as suggested in this report. By doing so, you could eliminate up-to ", $cnt_eliminated, " out of ",$cnt_acls_total," ACL entries in the ", $cnt_fws, " firewall(s)!\n";
		close(OUT);
		print "Done saving report!\n";
	} else {
		print "\nBy using the Cisco 'object group' feature to combine the ACL entries within the above groups, you could eliminate ", $cnt_eliminated, " out of ", $cnt_acls_total, " ACL entries in the ", $cnt_fws, " firewall(s)!\n";
	}
}

sub print_loose_rule_report () {
  #
  ## Print out loose ACL entry reports
  #
 	my $count=0;
	my $count_group=0;
	my %loose_description = ("source", "The ACL entry's source IP is unlimited 'any'",
           "destination", "The ACL entry's destination IP is unlimited 'any'",
           "service", "The ACL entry's destination service port is unlimited 'any'"
	);
	if (defined $opts{output}) {
		print "\n\nSaving the loose rule report into file: ",$opts{output}, "\n...\n";
		open (OUT, ">", $opts{output}) || die " Can't open file for write access: $opts{output} : $!\n";
	}
	if (defined $opts{output}) {
		print OUT "\n\nFirewall ", $_[0], " Loose Rule Report\n";
		print OUT "Loose Rule By ", $_[0], " - ", $loose_description{$_[0]}, "\n";
		print OUT "Total ACLs audited in $cnt_fws firewall(s): $cnt_acls_total \n\n\n";
	} else {
		print "\n\nFirewall ", $_[0], " Loose Rule Report\n";
		print "Loose Rule By ", $_[0], " - ", $loose_description{$_[0]}, "\n";
		print "Total ACLs audited in $cnt_fws firewall(s): $cnt_acls_total \n\n\n";
	}
	foreach my $key (keys %{$LOOSE_RULE{$loose_rule}}) {
		$count_group++;
		$count=$count+$LOOSE_RULE{$_[0]}{$key}{count};
		if (defined $opts{output}) {
			print OUT "ACL Loose Rule Group ",$count_group," on Firewall: $LOOSE_RULE{$_[0]}{$key}{firewall}", ", Interface: ", $LOOSE_RULE{$_[0]}{$key}{interface}, ":\n";
			print OUT "Sub-total: ", $LOOSE_RULE{$_[0]}{$key}{count}, " entries\n";
			my @entries= @{$LOOSE_RULE{$_[0]}{$key}{entries}};
			foreach (@entries) {
				print OUT "$_\n";
			}
			print OUT "\n";
		} else {
			print "ACL Loose Rule Group ",$count_group," on Firewall: $LOOSE_RULE{$_[0]}{$key}{firewall}", ", Interface: ", $LOOSE_RULE{$_[0]}{$key}{interface}, ":\n";
			print "Sub-total: ", $LOOSE_RULE{$_[0]}{$key}{count}, " entries\n";
			my @entries= @{$LOOSE_RULE{$_[0]}{$key}{entries}};
			foreach (@entries) {
				print "$_\n";
			}
			print "\n";
		}
	}
	if (defined $opts{output}) {
		print OUT "\nWe find a total of ",$count," loose rule(s) out of ",$cnt_acls_total," ACL entries in the ", $cnt_fws, " firewall(s)!\n";
		close(OUT);
		print "Done saving report!\n";
	} else {
		print "\nWe find a total of ",$count," loose rule(s) out of ",$cnt_acls_total," ACL entries in the ", $cnt_fws, " firewall(s)!\n";
	}
}

sub print_unused_object () {
  #
  ## Print out clean up report of the unused object
  #
	my $count_acl=0;
	my $count_fw=0;
	if (defined $opts{output}) {
		print "\n\nSaving the unused object report into file: ",$opts{output}, " ...\n";
		open (OUT, ">", $opts{output}) || die " Can't open file for write access: $opts{output} : $!\n";
	}
	if (defined $opts{output}) {
		print OUT "\n\nFirewall Unused Object Report\n";
		print OUT "Object Type: ", $_[0], "\n";
	} else {
		print "\n\nFirewall Unused Object Report\n";
		print "Object Type: ", $_[0], "\n";
	}
	foreach my $fw (keys %UNUSED) {
		$count_fw++;
		if (defined $opts{output}) {
			print OUT "\nUnused Object In firewall: ", $fw, "\n";
		} else {
			print "\nUnused ",$opts{clean}, " In firewall: ", $fw, "\n";
		}
		foreach (@{$UNUSED{$fw}{entry}}) {
			$count_acl++;
			if (defined $opts{output}) {
				print OUT $_, "\n";
			} else {
				print $_, "\n";
			}
		}
	}
	if (defined $opts{output}) {
		print OUT "\nA total of ",$count_acl," unused ", $_[0], " entries are found in ",$count_fw, " firewall(s)!\n";
		close(OUT);
		print "Done saving report!\n";
	} else {
		print "\nA total of ",$count_acl," unused ", $_[0], " entries are found in ",$count_fw, " firewall(s)!\n";
	}
}

sub print_banner {
  #
  ## Print out the banner in ascii art format (running train pattern) - you know the graphic count!
  #
	print "="x80, "\n";
	print <<ASCII;
   ___    ___    ___   _  __          ___    ___    _      ___
  | _ \  |_ _|  / __| | |/ /         / __|  /   \  | |    / __|
  |   /   | |   \__ \ | ' <    ___  | (__   | - |  | |__ | (__
  |_|_\  |___|  |___/ |_|\_\  |___|  \___|  |_|_|  |____| \___|
_|"""""||"""""||"""""||"""""||"""""||"""""||"""""||"""""||"""""|
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

ASCII
	print "Version: ", $ver, "\n", "Designed and Developed by: ", $author, "\n";
	print "="x80,"\n\n";
}
