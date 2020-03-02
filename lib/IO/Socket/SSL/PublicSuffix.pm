
use strict;
use warnings;
package IO::Socket::SSL::PublicSuffix;
use Carp;

# for updates
use constant URL => 'http://publicsuffix.org/list/effective_tld_names.dat';

=head1 NAME

IO::Socket::SSL::PublicSuffix - provide access to Mozilla's list of effective TLD names

=head1 SYNOPSIS

    # use builtin default
    use IO::Socket::SSL::PublicSuffix;
    $ps = IO::Socket::SSL::PublicSuffix->default;

    # load from string
    $ps = IO::Socket::SSL::PublicSuffix->from_string("*.uk\n*");

    # load from file or file handle
    $ps = IO::Socket::SSL::PublicSuffix->from_file($filename);
    $ps = IO::Socket::SSL::PublicSuffix->from_file(\*STDIN);


    # --- string in -> string out
    # $rest -> whatever.host
    # $tld  -> co.uk
    my ($rest,$tld) = $ps->public_suffix('whatever.host.co.uk');
    my $tld = $ps->public_suffix('whatever.host.co.uk');

    # $root_domain -> host.co.uk
    my $root_domain = $ps->public_suffix('whatever.host.co.uk', 1);

    # --- array in -> array out
    # $rest -> [qw(whatever host)]
    # $tld  -> [qw(co uk)]
    my ($rest,$tld) = $ps->public_suffix([qw(whatever host co uk)]);

 ----

    # To update this file with the current list:
    perl -MIO::Socket::SSL::PublicSuffix -e 'IO::Socket::SSL::PublicSuffix::update_self_from_url()'



=head1 DESCRIPTION

This module uses the list of effective top level domain names from the mozilla
project to determine the public top level domain for a given hostname.

=head2 Method

=over 4

=item class->default(%args)

Returns object with builtin default.
C<min_suffix> can be given in C<%args> to specify the minimal suffix, default
is 1.

=item class->from_string(string,%args)

Returns object with configuration from string.
See method C<default> for C<%args>.

=item class->from_file( file name| file handle, %args )

Returns object with configuration from file or file handle.
See method C<default> for C<%args>.

=item $self->public_suffix( $host|\@host, [ $add ] )

In array context the function returns the non-tld part and the tld part of the
given hostname, in scalar context only the tld part.
It adds C<$add> parts of the non-tld part to the tld, e.g. with C<$add=1> it
will return the root domain.

If there were no explicit matches against the public suffix configuration it
will fall back to a suffix of length 1.

The function accepts a string or an array-ref (e.g. host split by C<.>). In the
first case it will return string(s), in the latter case array-ref(s).

International hostnames or labels can be in ASCII (IDNA form starting with
C<xn-->) or unicode. In the latter case an IDNA handling library like
L<Net::IDN:::Encode>, L<Net::LibIDN> or recent versions of L<URI> need to be
installed.

=item ($self|class)->can_idn

Returns true if IDN support is available.

=back

=head1 FILES

http://publicsuffix.org/list/effective_tld_names.dat

=head1 SEE ALSO

Domain::PublicSuffix, Mozilla::PublicSuffix

=head1 BUGS

 Q: Why yet another module, we already have L<Domain::PublicSuffix> and
    L<Mozilla::PublicSuffix>.
 A: Because the public suffix data change more often than these modules do,
    IO::Socket::SSL needs this list and it is more easy this way to keep it
    up-to-date.


=head1 AUTHOR

Steffen Ullrich

=cut


BEGIN {
    if ( eval {
	require URI::_idna;
	defined &URI::_idna::encode && defined &URI::_idna::decode
    }) {
	*idn_to_ascii   = \&URI::_idna::encode;
	*idn_to_unicode = \&URI::_idna::decode;
	*can_idn = sub { 1 };
    } elsif ( eval { require Net::IDN::Encode } ) {
	*idn_to_ascii   = \&Net::IDN::Encode::domain_to_ascii;
	*idn_to_unicode = \&Net::IDN::Encode::domain_to_unicode;
	*can_idn = sub { 1 };
    } elsif ( eval { require Net::LibIDN; require Encode } ) {
	# Net::LibIDN does not use utf-8 flag and expects raw data
	*idn_to_ascii   = sub { 
	    Net::LibIDN::idn_to_ascii(Encode::encode('utf-8',$_[0]),'utf-8');
	},
	*idn_to_unicode = sub { 
	    Encode::decode('utf-8',Net::LibIDN::idn_to_unicode($_[0],'utf-8'));
	},
	*can_idn = sub { 1 };
    } else {
	*idn_to_ascii   = sub { croak "idn_to_ascii(@_) - no IDNA library installed" };
	*idn_to_unicode = sub { croak "idn_to_unicode(@_) - no IDNA library installed" };
	*can_idn = sub { 0 };
    }
}

{
    my %default;
    sub default {
	my (undef,%args) = @_;
	my $min_suffix = delete $args{min_suffix};
	$min_suffix = 1 if ! defined $min_suffix;
	%args and die "unknown args: ".join(" ",sort keys %args);
	return $default{$min_suffix} ||= shift->from_tree(_latest_tree(),
	    min_suffix => $min_suffix);
    }
}

sub from_tree {
    my($class,$tree_hr,%args) =@_;
    my $min_suffix = delete $args{min_suffix};
    $min_suffix = 1 if ! defined $min_suffix;
    %args and die "unknown args: ".join(" ",sort keys %args)
return bless { 
	tree => $tree_hr, 
	min_suffix => $min_suffix 
    },$class;
}

sub from_string {
    my $class = shift;
    my $data  = shift;
    open( my $fh,'<', \$data );
    return $class->from_file($fh,@_);
}

sub from_file {
    my ($class,$file,%args) = @_;
    my $min_suffix = delete $args{min_suffix};
    $min_suffix = 1 if ! defined $min_suffix;
    %args and die "unknown args: ".join(" ",sort keys %args);

    my $fh;
    if ( ref($file)) {
	$fh = $file
    } elsif ( ! open($fh,'<',$file)) {
	die "failed to open $file: $!";
    }
    my $tree_hr = build_tree_from_fh($fh);
    return bless { 
	tree => $tree_hr, 
	min_suffix => $min_suffix 
    },$class;
}

sub build_tree_from_fh {    
    my %tree;
    local $/ = "\n";
    while ( my $line = <$fh>) {
	$line =~s{//.*}{};
	$line =~s{\s+$}{};
	$line eq '' and next;
	my $p = \%tree;
	$line = idn_to_ascii($line) if $line !~m{\A[\x00-\x7f]*\Z};
	my $not = $line =~s{^!}{};
	my @path = split(m{\.},$line);
	for(reverse @path) {
	    $p = $p->{$_} ||= {}
	}
	$p->{'\0'} = $not ? -1:1;
    }
    return \%tree;
}

sub public_suffix {
    my ($self,$name,$add) = @_;
    my $want; # [a]rray, [s]tring, [u]nicode-string
    if ( ref($name)) {
	$want = 'a';
	$name = [ @$name ]; # don't change input
    } else {
	return if ! defined $name;
	if ( $name !~m{\A[\x00-\x7f]*\Z} ) {
	    $name = idn_to_ascii($name);
	    $want = 'u';
	} else {
	    $want = 's';
	}
	$name = lc($name);
	$name =~s{\.$}{};
	$name = [ $name =~m{([^.]+)}g ];
    }
    @$name or return;
    $_ = lc($_) for(@$name);

    my (%wild,%host,%xcept,@stack,$choices);
    my $p = $self->{tree};
    for( my $i=0; $i<@$name; $i++ ) {
	$choices = [];
	if ( my $px = $p->{ $name->[$#$name-$i] } ) {
	    # name match, continue with next path element
	    push @$choices,$px;
	    if ( my $end = $px->{'\0'} ) {
		( $end>0 ? \%host : \%xcept )->{$i+1} = $end;
	    }
	}
	if ( my $px = $p->{'*'} ) {
	    # wildcard match, continue with next path element
	    push @$choices,$px;
	    if ( my $end = $px->{'\0'} ) {
		( $end>0 ? \%wild : \%xcept )->{$i+1} = $end;
	    }
	}


	next_choice:
	if ( @$choices ) {
	    $p = shift(@$choices);
	    push @stack, [ $choices, $i ] if @$choices;
	    next; # go deeper
	}

	# backtrack
	@stack or last;
	($choices,$i) = @{ pop(@stack) };
	goto next_choice;
    }

    #warn Dumper([\%wild,\%host,\%xcept]); use Data::Dumper;


    # remove all exceptions from wildcards
    delete @wild{ keys %xcept } if %xcept;
    # get longest match
    my ($len) = sort { $b <=> $a } (
	keys(%wild), keys(%host), map { $_-1 } keys(%xcept));
    # if we have no matches use a minimum of min_suffix
    $len = $self->{min_suffix} if ! defined $len;
    $len += $add if $add;
    my $suffix;
    if ( $len < @$name ) {
	$suffix = [ splice( @$name, -$len, $len ) ];
    } elsif ( $len > 0 ) {
	$suffix = $name;
	$name = []
    } else {
	$suffix = []
    }

    if ( $want ne 'a' ) {
	$suffix = join('.',@$suffix);
	$name = join('.',@$name);
	if ( $want eq 'u' ) {
	    $suffix = idn_to_unicode($suffix);
	    $name   = idn_to_unicode($name);
	}
    }

    return wantarray ? ($name,$suffix):$suffix;
}


{
    my $tree_hr;
    sub _latest_tree {
	if ( ! defined $tree_hr ) {
      eval { require IO::Socket::SSL::PublicSuffix::Latest; }
      if (!$@) {
        $tree_hr = IO::Socket::SSL::PublicSuffix::Latest::get_tree();
      } else {
        require IO::Socket::SSL::PublicSuffix::BuiltIn;
        $tree_hr = IO::Socket::SSL::PublicSuffix::BuiltIn::get_tree();
      }
	}
	return $data;
    }
}

sub update_self_from_url {
    my $url = shift || URL();
    my $dst = __FILE__;
    -w $dst or die "cannot write $dst";
    open( my $fh,'<',$dst ) or die "open $dst: $!";
    my $code = '';
    local $/ = "\n";
    while (<$fh>) {
	$code .= $_;
	m{<<\'END_BUILTIN_DATA\'} and last;
    }
    my $tail;
    while (<$fh>) {
	m{\AEND_BUILTIN_DATA\r?\n} or next;
	$tail = $_;
	last;
    }
    $tail .= do { local $/; <$fh> };
    close($fh);

    require LWP::UserAgent;
    my $resp = LWP::UserAgent->new->get($url)
	or die "no response from $url";
    die "no success url=$url code=".$resp->code." ".$resp->message 
	if ! $resp->is_success;
    my $content = $resp->decoded_content;
    while ( $content =~m{(.*\n)}g ) {
	my $line = $1;
	if ( $line =~m{\S} && $line !~m{\A\s*//} ) {
	    $line =~s{//.*}{};
	    $line =~s{\s+$}{};
	    $line eq '' and next;
	    if ( $line !~m{\A[\x00-\x7f]+\Z} ) {
		$line = idn_to_ascii($line);
	    }
	    $code .= "$line\n";
	} else {
	    $code .= "$line";
	}
    }

    open( $fh,'>:utf8',$dst ) or die "open $dst: $!";
    print $fh $code.$tail;
}

1;
