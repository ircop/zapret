#!/usr/bin/perl -w

# TODO:
# + RESOLVERS
# - IP blockinig when no other params in content block
# - Subnet blocking when no other params in content block
# + Content cleanup after removal
# + Mail functions
# + Mail new ips
# + Mail excludes
# + Mail new domains, urls, subnets
# + Mail deleted stuff
# + Excludes
# + utf md5

use strict;
use warnings;
use SOAP::Lite;
use DBI;
use Data::Dumper;
use MIME::Base64;
use utf8;
use XML::Simple;
use URI;
use NetAddr::IP;
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Encode qw(encode_utf8);
use Net::Nslookup;
use Net::SMTP;
use POSIX;
use POSIX qw(strftime);

######## Config #########

#my $api_url = "http://vigruzki.rkn.gov.ru/services/OperatorRequestTest/?wsdl";
my $api_url = "http://vigruzki.rkn.gov.ru/services/OperatorRequest/?wsdl";

my $debug = 1;

# THIS MUST BE IN CP1251! 
my $operator_name = 'ООО "Рога и Копыта"';
my $inn = '1231231231';
my $ogrn = '1231231231231';
my $email = 'noc@provider.com';

# Files and dirs
my $dir = '/opt/zapret';
my $req_file = $dir.'/req2.xml';
my $sig_file = $dir.'/req2.xml.sig';

my $db_host = 'db.provider.com';
my $db_user = 'zapret';
my $db_pass = 'zapret_pw';
my $db_name = 'zapret_db';

my $resolve = 1;
my @resolvers = (
    '10.10.10.10',
    '8.8.8.8'
);

# Mail:
#my @mail_to = ( 'wingman@ip-home.net', 'noc@ip-home.net' );
my @mail_to = ( 'noc@ip-home.net' );
my $smtp_from = 'zapret@ip-home.net';
my $smtp_host = '109.206.159.40';
my $smtp_port = 25;
my $smtp_login = 'zapret@provider.com';
my $smtp_password = 'zapret_mail_pw';
my $mail_excludes = 1;
my $mail_new = 1;
my $mail_new_ips = 1;
my $mail_removed = 1;
my $mail_removed_ips = 1;
my $mail_alone = 1;			# Mail if there are subnets without domain/url in record

######## End config #####

#binmode(STDOUT, ':utf8');
my $DBH;
my ($lastDumpDateOld, $lastAction, $lastCode, $lastResult);
dbConnect();
getParams();

my %NEW = ();
my %OLD = ();
my %OLD_IPS = ();
my %OLD_DOMAINS = ();
my %OLD_URLS = ();
my %OLD_SUBNETS = ();
my %OLD_TRUE = ();
my %OLD_TRUE_IPS = ();
my %OLD_TRUE_DOMAINS = ();
my %OLD_TRUE_URLS = ();
my %OLD_TRUE_SUBNETS = ();
my %NEW_RECORDS = ();
my %NEW_DOMAINS = ();
my %NEW_URLS = ();
my %NEW_IPS = ();
my %NEW_SUBNETS = ();
my %EX_IPS = ();
my %EX_DOMAINS = ();
my %EX_SUBNETS = ();

my $MAILTEXT = '';
my $MAIL_ADDED = '';
my $MAIL_ADDED_IPS = '';
my $MAIL_REMOVED = '';
my $MAIL_REMOVED_IPS = '';
my $MAIL_EXCLUDES = '';
my $MAIL_ALONE = '';

debug("Last dump date:\t".$lastDumpDateOld);
debug("Last action:\t".$lastAction);
debug("Last code:\t".$lastCode);
debug("Last result:\t".$lastResult);

#############################################################

# default action:
my $act=0;
if( $lastAction eq 'sendRequest' || $lastAction eq '' ) {
    if( $lastResult eq 'send' ) {
	getResult();
	$act=1;
    } else {
	sendRequest();
	$act=1;
    }
}

if( $lastAction eq 'getResult' ) {
    if( $lastResult eq 'err' ) {
	sendRequest();
	$act=1;
    } else {
	checkDumpDate();
	$act=1;
    }
}

if( $lastAction eq 'getLastDumpDate' ) {
    checkDumpDate();
    $act=1;
}

if( $act == 0 ) {
    sendRequest();
}

#############################################################


sub getResult {
    debug("Getting result...");
    
    my $soap = SOAP::Lite->service( $api_url );
    my @result = $soap->getResult( $lastCode );
    
    if( !($result[0] eq 'true' ) ) {
	# Some error
	my $comment = $result[1];
#	    binmode(STDOUT, ':utf8');
	    print "Can not get result: ".$comment."\n";
#	print Dumper(@result);
	# This is utf-8:
	if( $result[2] == 0 ) {
	    print "Query pending ( code: 0 )\n";
    	    exit;
    	} else {
    	    set('lastResult', 'err');
    	    set('lastAction', 'getResult');
    	    exit;
    	}
    } else {
	unlink $dir.'/dump.xlm';
	unlink $dir.'/arch.zip';
	unlink $dir.'/dump.xml.sig';
	
	my $zip = decode_base64($result[1]);

	open F, '>'.$dir.'/arch.zip' || die "Can't open arch.zip for writing!\n".$! ;
	binmode F;
	print F $zip;
	close F;
	
	`unzip -o $dir/arch.zip -d $dir/`;
	debug("Got result, parsing dump.");
	
	set('lasltAction', 'getResult');
	set('lastResult', 'got');
	set('lastDumpDate', time);
	
	parseDump();
    }
}


sub checkDumpDate {
    debug("Checking dump date...");
    my $lastDumpDate = getLastDumpDate();
    debug("RKN last dump date: ".$lastDumpDate);
    
    if( $lastDumpDateOld eq '' || $lastDumpDate > $lastDumpDateOld ) {
	# Update needed
	debug("Last dump date > prev. dump date. Updating.");
	if( sendRequest() == 1 ) {
	    debug("Updating lastDumpDate = ".$lastDumpDate);
	    set('lastDumpDate', $lastDumpDate);
	    set('lastActionDate', time);
	    return 1;
	}
    } else {
	debug("lastDumpDate <= prev. dump date. Exiting.");
	set('lastAction', 'getLastDumpDate');
	set('lastResult', 'old');
	set('lastActionDate', time);
	exit;
    }
}
sub getLastDumpDate
{
    my $soap= SOAP::Lite->service( $api_url );
    my @result = $soap->getLastDumpDateEx();
    if( $result[0] !~ /^(\d+)$/ ) {
	print "Can't get lastDumpDateEx!";
	print Dumper(@result);
	exit;
    } else {
	my $stamp = $result[0] / 1000;
	return $stamp;
    }
}

sub formRequest {
	my $now = time();
	my $tz = strftime("%z", localtime($now));
	$tz =~ s/(\d{2})(\d{2})/$1:$2/;
	my $dt = strftime("%Y-%m-%dT%H:%M:%S", localtime($now)) . $tz;
	
	my $txt = '<?xml version="1.0" encoding="windows-1251"?>
<request>
<requestTime>'.$dt.'</requestTime>
<operatorName>'.$operator_name.'</operatorName>
<inn>'.$inn.'</inn>
<ogrn>'.$ogrn.'</ogrn>
<email>'.$email.'</email>
</request>
';
	
	open F, '>'.$req_file || die $!;
		binmode(F, ':utf8');
		print F $txt;
	close F;
	
	# Signature
	`openssl smime -sign -in $req_file -out $sig_file -binary -signer $dir/cert.pem -outform DER`;
};

sub sendRequest {
    debug( "Sending request...");
    
    formRequest();
    
    my ( $req, $sig, $buf );
    
    # request
    open F, '<'.$req_file || die $!;
    binmode F;
    while( (read F, $buf, 65536) != 0 ) {
	$req .= $buf;
    }
    close F;
    
    # signature
    open F, '<'.$sig_file || die $!;
    binmode F;
    while( (read F, $buf, 65536) != 0 ) {
	$sig .= $buf;
    }
    close F;
    
    my $soap = SOAP::Lite->service( $api_url );
    my @result =  $soap->sendRequest(
	$req,
	$sig,
	"2.0"
    );
    
    my $res = $result[0];
    if( $res eq 'true' ) {
	# Everyhing OK
	my $code = $result[2];
	debug( $result[1] );
	set('lastCode', $code);
	set('lastAction', 'sendRequest');
	set('lastActionDate', time );
	set('lastResult', 'send');
	return 1;
    } else {
	# Something goes wrong
	my $code = $result[1];
	debug("ERROR while sending request: ".$code);
	set('lastResult', 'err');
	die;
    }
    
    binmode(STDOUT, ':utf8');
};


sub dbConnect {
    $DBH = DBI->connect_cached("DBI:mysql:database=".$db_name.";host=".$db_host,
    $db_user,
    $db_pass) or die DBI->errstr;
};

sub debug {
    my $txt = shift;
    if( $debug == 1 ) {
        print "DEBUG: " . $txt . "\n";
    }
};

sub set {
    my $param = shift;
    my $value = shift;
    my $sth = $DBH->prepare("UPDATE zap2_settings SET value = ? WHERE param = ?");
    $sth->bind_param(1, $value);
    $sth->bind_param(2, $param);
    $sth->execute or die DBI->errstr;
};
sub getParams {
    my $sth = $DBH->prepare("SELECT param,value FROM zap2_settings");
    $sth->execute or die DBI->errstr;
    while( my $ref = $sth->fetchrow_arrayref ) {
	if( $$ref[0] eq 'lastDumpDate' ) {
	    $lastDumpDateOld = $$ref[1];
	}
	if( $$ref[0] eq 'lastAction' ) {
	    $lastAction = $$ref[1];
	}
	if( $$ref[0] eq 'lastCode' ) {
	    $lastCode = $$ref[1];
	}
	if( $$ref[0] eq 'lastResult' ) {
	    $lastResult = $$ref[1];
	}
    }
};


sub parseDump
{
    debug("Parsing dump...");
    
    my $xml = new XML::Simple;
    my $data = $xml->XMLin($dir.'/dump.xml');
    
#    print Dumper($data->{content});
    
    foreach my $k (keys $data->{content}) {
	eval {
	my ( $decision_number, $decision_org, $decision_date, $entry_type, $include_time );
	$decision_number = $decision_org = $decision_date = $entry_type = '';
	my $decision_id = $k;
	$entry_type = '';
	    my $content = $data->{content}->{$k};
	    $decision_number = $content->{decision}->{number} if defined( $content->{decision}->{number} );
	    $decision_org = $content->{decision}->{org} if defined( $content->{decision}->{org} );
	    $decision_date = $content->{decision}->{date} if defined( $content->{decision}->{org} );
	    $entry_type = $content->{entryType} if defined( $content->{entryType} );
	    $include_time = $content->{includeTime} if defined( $content->{includeTime} );
	
	my %item = (
	    'entry_type'	=> $entry_type,
	    'decision_num'	=> $decision_number,
	    'decision_id'	=> $decision_id,
	    'decision_date'	=> $decision_date,
	    'decision_org'	=> $decision_org,
	    'include_time'	=> $include_time
	);
	my @domains = ();
	my @urls = ();
	my @ips = ();
	my @subnets = ();
	    
	    # Domains
	    if( defined( $content->{domain} ) ) {
		if(ref($content->{domain}) eq 'ARRAY') {
		    foreach( @{$content->{domain}} ) {
			push @domains, $_;
		    }
		} else {
		    push @domains, $content->{domain};
		}
	    }
	    $item{'domains'} = \@domains;
	    
	    # URLs
	    if( defined( $content->{url} ) ) {
		if( ref($content->{url}) eq 'ARRAY' ) {
		    foreach( @{$content->{url}} ) {
			push @urls, $_;
		    }
		} else {
		    push @urls, $content->{url};
		}
	    }
	    $item{'urls'} = \@urls;
	    
	    # IPs
	    if( defined( $content->{ip} ) ) {
		if( ref($content->{ip}) eq 'ARRAY' ) {
		    foreach( @{$content->{ip}} ) {
			push @ips, $_;
		    }
		} else {
		    push @ips, $content->{ip};
		}
	    }
	    $item{'ips'} = \@ips;
	
	    # Subnets
	    if( defined( $content->{ipSubnet} ) ) {
		if( ref($content->{ipSubnet}) eq 'ARRAY' ) {
		    foreach( @{$content->{ipSubnet}} ) {
			push @subnets, $_;
		    }
		} else {
		    push @subnets, $content->{ipSubnet};
		}
	    }
	    $item{'subnets'} = \@subnets;
	
#	    debug( " -- Decision (id ".$decision_id."): ".$decision_number.", from ".$decision_date.", org: ".$decision_org." \n" );
	
#	    print Dumper( \%item );
	$NEW{$decision_id} = \%item;
	};
	print "Eval! ".$@ if $@;
    }
	
	# Dump parsed.
	# Get old data from DB
	getOld();
	
	processNew();
	clearOld();
	processMail();
	
	set('lastAction', 'getResult');
	set('lastResult', 'got');
	set('lastDumpDate', time() );
};

# Cleanup old entries
sub clearOld {
	foreach my $domain ( keys %OLD_TRUE_DOMAINS ) {
		if( !defined($NEW_DOMAINS{$domain}) ) {
			delDomain( $OLD_TRUE_DOMAINS{$domain}[0], $OLD_TRUE_DOMAINS{$domain}[1] );
#			debug("Deleting domain id ".$OLD_TRUE_DOMAINS{$domain}[0]." ( ".$OLD_TRUE_DOMAINS{$domain}[1]." )");
		}
	}
	foreach my $url ( keys %OLD_TRUE_URLS ) {
		if( !defined($NEW_URLS{$url}) ) {
			delUrl( $OLD_TRUE_URLS{$url}[0], $OLD_TRUE_URLS{$url}[1] );
#			debug("Deleting url id ".$OLD_TRUE_URLS{$url}[0]." (".$OLD_TRUE_URLS{$url}[1].")");
		}
	}
	foreach my $ip ( keys %OLD_TRUE_IPS ) {
		if( !defined($NEW_IPS{$ip}) ) {
			delIp( $OLD_TRUE_IPS{$ip}[0], $OLD_TRUE_IPS{$ip}[1] );
#			debug("Deleting IP id ".$OLD_TRUE_IPS{$ip}[0]." (".$OLD_TRUE_IPS{$ip}[1].")");
		}
	}
	foreach my $net ( keys %OLD_TRUE_SUBNETS ) {
		if( !defined($NEW_SUBNETS{$net}) ) {
			delSubnet( $OLD_TRUE_SUBNETS{$net}[0], $OLD_TRUE_SUBNETS{$net}[1] );
#			debug("Deleting subnet id ".$OLD_TRUE_SUBNETS{$net}[0]." (".$OLD_TRUE_SUBNETS{$net}[1].")");
		}
	}
	foreach my $item ( keys %OLD_TRUE ) {
		if( !defined($NEW{$item}) ) {
			#print $OLD_TRUE{$item}->{id};
#			debug("Deleting decision record of id ".$OLD_TRUE{$item}->{id});
			delRecord($OLD_TRUE{$item}->{id} );
		}
	}
};

sub processNew {
	my $sth;
    eval {
	# Content items:
	foreach my $d_id ( keys %NEW ) {
		
		my $record_id = 0;
		if( !defined( $OLD{$d_id} ) ) {
		    # New record
		    $sth = $DBH->prepare("INSERT INTO zap2_records(decision_id,decision_date,decision_num,decision_org,include_time,entry_type) VALUES(?,?,?,?,?,?)");
		    $sth->bind_param(1, $d_id );
		    $sth->bind_param(2, $NEW{$d_id}->{decision_date} );
		    $sth->bind_param(3, $NEW{$d_id}->{decision_num} );
		    $sth->bind_param(4, $NEW{$d_id}->{decision_org} );
		    $sth->bind_param(5, $NEW{$d_id}->{include_time} );
		    $sth->bind_param(6, $NEW{$d_id}->{entry_type} );
		    $sth->execute;
		    $record_id = $sth->{mysql_insertid};
		    $OLD{$d_id} = $record_id;
		    $MAIL_ADDED .= "Added new content: id ".$record_id."\n";
		    debug("Added new content: id ".$record_id);
		} else {
		    $record_id = $OLD{$d_id}->{id};
		}
		$NEW_RECORDS{$d_id} = 1;
		
		# Domain items:
		if( ref($NEW{$d_id}->{domains}) eq 'ARRAY' ) {
		    foreach( @{$NEW{$d_id}->{domains}} ) {
			my $domain = $_;
			
			# Check for excludes
			if( defined( $EX_DOMAINS{$domain} ) ) {
#				print "EXCLUDE DOMAIN: ".$domain."\n";
				$MAIL_EXCLUDES .= "Excluding domain: ".$domain."\n";
				debug("Excluding domain: ".$domain);
				next;
			}
			
			Resolve( $domain, $record_id );
			
			if( !defined( $OLD_DOMAINS{md5_hex(encode_utf8($domain))} ) ) {
#				print "New domain: ".$domain."\n";
				$sth = $DBH->prepare("INSERT INTO zap2_domains(record_id, domain) VALUES(?,?)");
				$sth->bind_param(1, $record_id);
				$sth->bind_param(2, $domain);
				$sth->execute;
				$OLD_DOMAINS{md5_hex(encode_utf8($domain))} = 1;
				$MAIL_ADDED .= "Added new domain: ".encode_utf8($domain)."\n";
				debug("Added new domain: ".encode_utf8($domain));
			}
			$NEW_DOMAINS{md5_hex(encode_utf8($domain))} = encode_utf8($domain);
		    }
		}
		
		# URLs
		if( ref($NEW{$d_id}->{urls}) eq 'ARRAY' ) {
			foreach( @{$NEW{$d_id}->{urls}} ) {
				my $url = $_;
				
				# Check for ex. domain
				my @res = ( $url =~ m!^(?:http://|https://)?([^(/|\?)]+)!i );
				my $url_domain = $res[0];
				
				Resolve( $url_domain, $record_id );
				
				if( defined( $EX_DOMAINS{$url_domain} ) ) {
#					binmode(STDOUT, ':utf8');
#					print "EXCLUDE DOMAIN ".$url_domain." (URL ".$url.")\n";
					$MAIL_EXCLUDES .= "Excluding URL (caused by excluded domain ".$url_domain."): ".encode_utf8($url)."\n";
					next;
				}
				
				if( !defined( $OLD_URLS{md5_hex(encode_utf8($url))} ) ) {
#				    binmode(STDOUT, ':utf8');
#				    print "New URL: ".encode_utf8($url)."\n";
#				    print "MD5 hex: ".md5_hex(encode_utf8($url))."\n";
				    $sth = $DBH->prepare("INSERT INTO zap2_urls(record_id, url) VALUES(?,?)");
				    $sth->bind_param(1, $record_id);
				    $sth->bind_param(2, $url);
				    $sth->execute;
				    $OLD_URLS{md5_hex(encode_utf8($url))} = 1;
				    $MAIL_ADDED .= "Added new URL: ".encode_utf8($url)."\n";
				    debug("Added new URL: ".encode_utf8($url));
				}
				$NEW_URLS{md5_hex(encode_utf8($url))} = encode_utf8($url);
			}
		}
		
		# Subnets
		if( ref($NEW{$d_id}->{subnets}) eq 'ARRAY' ) {
			foreach( @{$NEW{$d_id}->{subnets}} ) {
				my $subnet = $_;
				
				
				my $exclude = 0;
				# Check for excludes. Ips:
				for my $ip (keys %EX_IPS) {
#					print $ip."\n";
					my $ipadr = NetAddr::IP->new( $ip );
					my $net = NetAddr::IP->new( $subnet );
					if( $ipadr && $net ) {
						if( $ipadr->within($net) ) {
#							print "Exclude subnet ".$subnet.": contains excluded IP ".$ip."\n";
							$MAIL_EXCLUDES .= "Excluding subnet ".$subnet.": contains excluded ip ".$ip."\n";
							debug("Excluding subnet ".$subnet);
							$exclude = 1;
						}
					}
				}
				# And nets:
				for my $net (keys %EX_SUBNETS) {
					my $net1 = NetAddr::IP->new( $net );
					my $net2 = NetAddr::IP->new( $net );
					if( $net1 && $net2 ) {
						if( $net1->within( $net2 ) || $net2->within( $net1 ) ) {
#							print "Exclude subnet ".$subnet.": overlaps with excluded net ".$net."\n";
							$MAIL_EXCLUDES .= "Excluding subnet ".$subnet.": overlaps with excluded net ".$net."\n";
							$exclude = 1;
							debug("Excluding subnet ".$subnet);
						}
					}
				}
				
				if( $exclude == 1 ) {
					next;
				}
				
				if( !defined( $OLD_SUBNETS{$subnet} ) ) {
#				    print "New subnet: ".$subnet."\n";
				    $sth = $DBH->prepare("INSERT INTO zap2_subnets(record_id, subnet) VALUES(?,?)");
				    $sth->bind_param(1, $record_id);
				    $sth->bind_param(2, $subnet);
				    $sth->execute;
				    $OLD_SUBNETS{$subnet} = 1;
				    $MAIL_ADDED .= "Added new subnet: ".$subnet."\n";
				    debug("Added new subnet: ".$subnet);

					# Check, if there no any othere parameters in this content
					if(
						( !defined($NEW{$d_id}->{domains}) || ref($NEW{$d_id}->{domains}) ne 'ARRAY' || scalar(@{$NEW{$d_id}->{domains}}) == 0 )
						&&
						( !defined($NEW{$d_id}->{urls}) || ref($NEW{$d_id}->{urls}) ne 'ARRAY' || scalar(@{$NEW{$d_id}->{urls}}) == 0 )
					) {
						$MAIL_ALONE .= "Alert! Subnet ".$subnet." added without any domain/url!\n";
					}

				}
				$NEW_SUBNETS{$subnet} = 1;
			}
		}
		
		# IPS
		if( ref($NEW{$d_id}->{ips}) eq 'ARRAY' ) {
			foreach( @{$NEW{$d_id}->{ips}} ) {
				my $ip = $_;
				
				my $exclude = 0;
				# Check excluded nets
				for my $subnet (keys %EX_SUBNETS) {
					my $ipadr = NetAddr::IP->new( $ip );
					my $net = NetAddr::IP->new( $subnet );
					if( $ipadr && $net ) {
						if( $ipadr->within($net) ) {
#							print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
							$MAIL_EXCLUDES .= "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
							debug("Excluding ip ".$ip);
							$exclude = 1;
						}
					}
				}
				if( $exclude == 1 ) {
					next;
				}
				
				# Check for ex. ip
				if( defined($EX_IPS{$ip}) ) {
#					print "Excluding ip ".$ip.": match excluded ip in DB.\n";
					$MAIL_EXCLUDES .= "Excluding ip ".$ip.": match excluded ip in DB.\n";
					debug("Excluding ip ".$ip);
					next;
				}
				
				if( !defined( $OLD_IPS{$ip} ) ) {
#					print "New ip: ".$ip."\n";
					$sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved) VALUES(?,inet_aton(?),0)");
					$sth->bind_param(1, $record_id);
					$sth->bind_param(2, $ip);
					$sth->execute;
					$OLD_IPS{$ip} = 1;
					$MAIL_ADDED_IPS .= "Added new IP: ".$ip."\n";
					debug("New ip: ".$ip);
				}
				$NEW_IPS{$ip} = 1;
			}
		}
	}
    };
	print "Eval: ".$@ if $@;
};

sub getOld {
	%OLD = ();
	%OLD_IPS = ();
	%OLD_DOMAINS = ();
	%OLD_SUBNETS = ();
	%OLD_URLS = ();
	%OLD_TRUE = ();
	%OLD_TRUE_IPS = ();
	%OLD_TRUE_DOMAINS = ();
	%OLD_TRUE_SUBNETS = ();
	%OLD_TRUE_URLS = ();
	# Contents
	my $sth = $DBH->prepare("SELECT id,date_add,decision_id,decision_date,decision_num,decision_org,include_time FROM zap2_records ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		my %item = (
			'id' => $$ref[0],
			'date_add' => $$ref[1],
			'decision_id' => $$ref[2],
			'decision_date' => $$ref[3],
			'decision_num' => $$ref[4],
			'decision_org' => $$ref[5],
			'include_time' => $$ref[6]
		);
		$OLD{$$ref[2]} = \%item;
		$OLD_TRUE{$$ref[2]} = \%item;
	}
	
	# Domains
	$sth = $DBH->prepare("SELECT record_id, domain, id FROM zap2_domains ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_DOMAINS{md5_hex($$ref[1])} = $$ref[0];
		@{$OLD_TRUE_DOMAINS{md5_hex($$ref[1])}} = ( $$ref[2], $$ref[1] );
	}
	
	# URLs
	$sth = $DBH->prepare("SELECT id,record_id,url FROM zap2_urls ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_URLS{md5_hex($$ref[2])} = $$ref[0];
		@{$OLD_TRUE_URLS{md5_hex($$ref[2])}} = ( $$ref[0], $$ref[2] );
	}
	
	# Subnets
	$sth = $DBH->prepare("SELECT record_id, subnet, id FROM zap2_subnets ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_SUBNETS{$$ref[1]} = $$ref[0];
		@{$OLD_TRUE_SUBNETS{$$ref[1]}} = ( $$ref[2], $$ref[1] );
	}
	
	# Ips
	$sth = $DBH->prepare("SELECT inet_ntoa(ip) AS ip, record_id, id FROM zap2_ips ORDER BY date_add");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$OLD_IPS{$$ref[0]} = $$ref[1];
		@{$OLD_TRUE_IPS{$$ref[0]}} = ( $$ref[2], $$ref[0] );
	}
	
	# Excludes
	$sth = $DBH->prepare("SELECT subnet FROM zap2_ex_nets");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_SUBNETS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT inet_ntoa(ip) FROM zap2_ex_ips");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_IPS{$$ref[0]} = 1;
	}
	$sth = $DBH->prepare("SELECT domain FROM zap2_ex_domains");
	$sth->execute or die DBI->errstr;
	while( my $ref = $sth->fetchrow_arrayref ) {
		$EX_DOMAINS{$$ref[0]} = 1;
	}
};

sub Resolve {
	my $domain = shift;
	my $record_id = shift;
	
	if( $resolve != 1 ) {
		return;
	}
	
	my @adrs = ();
	eval {
		@adrs = nslookup(domain => $domain, server => \@resolvers, timeout => 4 );
	};
	foreach( @adrs ) {
		my $ip = $_;
		if( defined( $OLD_IPS{$ip} ) ) {
			next;
		}
		my $exclude = 0;
		for my $subnet (keys %EX_SUBNETS) {
			my $ipadr = NetAddr::IP->new( $ip );
			my $net = NetAddr::IP->new( $subnet );
			if( $ipadr && $net ) {
				if( $ipadr->within($net) ) {
					print "Excluding ip ".$ip.": overlaps with excluded subnet ".$subnet."\n";
					debug("Excluding ip ".$ip);
					$MAIL_EXCLUDES .= "Excluding new ip: ".$ip."\n";
					$exclude = 1;
				}
			}
		}
		if( defined($EX_IPS{$ip}) ) {
			debug("Excluding ip ".$ip);
			$exclude = 1;
		}
		
		if( $exclude == 1 ) {
			next;
		}
		
		# Not in old ips, not in excludes...
		my $sth = $DBH->prepare("INSERT INTO zap2_ips(record_id, ip, resolved) VALUES(?,inet_aton(?),1)");
		$sth->bind_param(1, $record_id);
		$sth->bind_param(2, $ip);
		$sth->execute;
		debug("New resolved ip: ".$ip." for domain ".$domain);
		$MAIL_ADDED_IPS .= "New resolved IP: ".$ip." for domain ".$domain."\n";
		$OLD_IPS{$ip} = 1;
	}
};

sub Mail {
	my $text = shift;
	
	setlocale(LC_TIME, "POSIX");
	
	foreach (@mail_to ) {
	
	    my $now = time();
	    my $timezone = strftime("%z", localtime($now));
	    my $datestring = strftime("Date: %a, %d %b %Y %H:%M:%S %z", localtime($now));
	
	    eval {
		my $to = $_;
		
		my $smtp = Net::SMTP->new($smtp_host.':'.$smtp_port, Debug => 0) or do { print "Can't connect to SMTP server; $!;"; return; };
	
		eval {
		    require MIME::Base64;
		    require Authen::SASL;
		} or do { print "Need MIME::Base64 and Authen::SASL to do smtp auth."; return; };
	
		$smtp->auth($smtp_login, $smtp_password) or do { print "Can't auth on smtp server; $!"; return; };
	
		$smtp->mail( $smtp_from );
		$smtp->recipient( $to );
	
		$smtp->data();
		$smtp->datasend("$datestring\n");
		$smtp->datasend("From: $smtp_from");
		$smtp->datasend("\n");
		$smtp->datasend("To: ".$to."\n");
		$smtp->datasend("Subject: zapret update!");
		$smtp->datasend("\n");
		$smtp->datasend( $text );
		$smtp->dataend();
		$smtp->quit;
	    };
	    print $@ if $@;
	}
};

sub delDomain {
	my $id = shift;
	my $domain = shift;
	
	debug("Removing domain ".$domain." (id ".$id.")");
	$MAIL_REMOVED .= "Removed domain ".$domain." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_domains WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
};

sub delUrl {
	my $id = shift;
	my $url = shift;

	debug("Removing URL ".$url." (id ".$id.")");
	$MAIL_REMOVED .= "Removed URL ".$url." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_urls WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
};
sub delIp {
	my $id = shift;
	my $ip = shift;
	
	debug("Removing IP ".$ip." (id ".$id.")");
	$MAIL_REMOVED_IPS .= "Removed IP ".$ip." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_ips WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
};
sub delSubnet {
	my $id = shift;
	my $subnet = shift;

	debug("Removing subnet ".$subnet." (id ".$id.")");
	$MAIL_REMOVED .= "Removed subnet ".$subnet." (id ".$id.")\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_subnets WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
};
sub delRecord {
	my $id = shift;
	
#	debug("Removing record ".$id);
	$MAIL_REMOVED .= "Removed record ".$id."\n";
	
	my $sth = $DBH->prepare("DELETE FROM zap2_records WHERE id=?");
	$sth->bind_param( 1, $id );
	$sth->execute;
};

sub processMail {
	if( $mail_alone == 1 && $MAIL_ALONE ne '' ) {
		$MAILTEXT .= "\n\n---- Standalone subnets! ----\n\n";
		$MAILTEXT .= $MAIL_ALONE;
	}
	if( $mail_excludes == 1 && $MAIL_EXCLUDES ne '' ) {
		$MAILTEXT .= "\n\n---- Excludes! ----\n\n";
		$MAILTEXT .= $MAIL_EXCLUDES;
	}
	if( $mail_removed == 1 &&  $MAIL_REMOVED ne '' ) {
		$MAILTEXT .= "\n\n--- Removed items: ---\n\n";
		$MAILTEXT .= $MAIL_REMOVED;
	}
	if( $mail_removed_ips == 1 && $MAIL_REMOVED_IPS ne '' ) {
		$MAILTEXT .= "\n\n--- Removed IPS: ---\n\n";
		$MAILTEXT .= $MAIL_REMOVED_IPS;
	}
	
	if( $mail_new == 1 && $MAIL_ADDED ne '' ) {
		$MAILTEXT .= "\n\n--- Added items: ---\n\n";
		$MAILTEXT .= $MAIL_ADDED;
	}
	if( $mail_new_ips == 1 && $MAIL_ADDED_IPS ne '' ) {
		$MAILTEXT .= "\n\n--- Added new ips: ---\n\n";
		$MAILTEXT .= $MAIL_ADDED_IPS;
	}

	
	if(  $MAILTEXT ne '' ) {
#		print "\n\n".$MAILTEXT."\n\n";
		Mail( $MAILTEXT );
	}
	
};

