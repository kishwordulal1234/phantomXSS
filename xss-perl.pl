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
print "\n                                     💀 PhantomXSS Scanner v2.0 💀\n";
print color('bold white');
print "                                  Advanced XSS Detection Framework\n";
print color('reset');
print "\n";

my ($url, $wordlist, $url_file, $scan_mode);

GetOptions(
    "u=s"   => \$url,
    "w=s"   => \$wordlist,
    "uw=s"  => \$url_file,
    "s=s"   => \$scan_mode
);

if (!\$url && !\$url_file) {
    die "Usage: perl xss-perl.pl -u <url> -w <payloads.txt> -s [all|r|d|sd]\n       or: perl xss-perl.pl -uw <url_list.txt> -w <payloads.txt> -s [all|r|d|sd]\n";
}

# 📂 Load payloads
$wordlist = $wordlist ? $wordlist : "payloads.txt";
open(my $fh, '<', $wordlist) or die "Could not open '$wordlist': $!\n";
my @payloads = <$fh>;
chomp @payloads;
close($fh);

# Limit payloads for faster testing
@payloads = @payloads[0..4] if @payloads > 5;

# 🌍 Load targets
my @targets;
if ($url_file) {
    open(my $ufh, '<', $url_file) or die "Could not open URL list: $url_file\n";
    @targets = <$ufh>;
    chomp @targets;
    close($ufh);
} else {
    push @targets, $url;
}

my $ua = LWP::UserAgent->new(timeout => 5); # Reduced timeout

foreach my $target_url (@targets) {
    my %visited;
    my @to_visit = ($target_url);

    print color('bold blue');
    print "\n[🌐] Starting PhantomXSS crawl on: $target_url\n";
    print color('reset');

    while (my $url = shift @to_visit) {
        next if $visited{$url}++;
        next unless $url =~ /^\Q$target_url/;

        my $res = $ua->get($url);
        next unless $res->is_success;

        print color('green'), "[✅] Crawled: $url\n", color('reset');

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
            scan_stored_xss($url);
        }
        if ($scan_mode eq 'all' || $scan_mode eq 'd') {
            scan_dom_xss($url);
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
                print color('bold red'), "[💥] Reflected XSS: ", color('reset');
                print color('red'), "$test_uri\n", color('reset');
            }
        }
    }
}

sub scan_stored_xss {
    my ($url) = @_;

    print color('bold yellow'), "[📝] Attempting Stored XSS on: $url\n", color('reset');

    my $mech = WWW::Mechanize->new(
        autocheck => 0, 
        timeout => 5,
        max_redirect => 2
    );
    
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(15); # 15 second timeout for entire function
        
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

        print color('yellow'), "[📝] Found " . scalar(@forms) . " form(s) on: $url\n", color('reset');

        # Test only first 2 forms and first 2 payloads for speed
        my $form_count = 0;
        FORM: for my $form_index (1 .. scalar(@forms)) {
            last if ++$form_count > 2; # Limit to 2 forms
            
            eval {
                $mech->get($url); # Reset to original page
                $mech->form_number($form_index);
                my $form = $mech->current_form;

                # Skip forms without text inputs
                my $has_text_input = 0;
                for my $input ($form->inputs) {
                    if ($input->type eq 'text' || $input->type eq 'textarea') {
                        $has_text_input = 1;
                        last;
                    }
                }
                next FORM unless $has_text_input;

                # Test only first 2 payloads for speed
                my $payload_count = 0;
                for my $payload (@payloads) {
                    last if ++$payload_count > 2;
                    
                    print color('yellow'), "[🔍] Testing payload: $payload\n", color('reset');
                    
                    # Fill form fields
                    for my $field ($form->inputs) {
                        next if $field->readonly || !$field->name;
                        next if $field->type eq 'submit' || $field->type eq 'hidden';
                        
                        if ($field->type eq 'text' || $field->type eq 'textarea') {
                            $mech->field($field->name, $payload);
                        }
                    }

                    # Submit form with timeout
                    eval {
                        local $SIG{ALRM} = sub { die "submit timeout\n" };
                        alarm(5);
                        $mech->click();
                        alarm(0);
                    };
                    
                    if ($@) {
                        print color('yellow'), "[⚠️] Form submission timeout or error\n", color('reset');
                        next;
                    }

                    # Check for stored XSS
                    if ($mech->content && $mech->content =~ /\Q$payload\E/) {
                        print color('bold magenta'), "[🔥] Stored XSS: ", color('reset');
                        print color('magenta'), "$url contains stored payload: $payload\n", color('reset');
                    }
                    
                    # Brief pause between payloads
                    sleep(0.5);
                }
            };
            
            if ($@) {
                print color('yellow'), "[⚠️] Error testing form $form_index: $@\n", color('reset');
                next FORM;
            }
        }
        
        alarm(0);
    };
    
    if ($@) {
        print color('yellow'), "[⚠️] Stored XSS scan timeout or error on: $url\n", color('reset');
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
                print color('bold cyan'), "[👁️] DOM XSS: ", color('reset');
                print color('cyan'), "$test_url\n", color('reset');
            }
        }
    }
}

print color('bold blue'), "\n[🏁] PhantomXSS scanning complete.\n\n", color('reset');
