use strict;
use warnings;
use FindBin;

use Test::More;

plan tests => 2;

{
    no warnings qw(once redefine);
    $INC{'IO/Socket/SSL/PublicSuffix/Latest.pm'} = '__DISABLED__';
    *IO::Socket::SSL::PublicSuffix::Latest::get_tree = sub { die "ensure fallback to BuiltIn"; };
    use warnings qw(once redefine);
}

require IO::Socket::SSL::PublicSuffix;

ok !$INC{'IO/Socket/SSL/PublicSuffix/BuiltIn.pm'}, "BuiltIn not loaded until requested";
my $ps = IO::Socket::SSL::PublicSuffix->default( min_suffix => 0 );
ok $INC{'IO/Socket/SSL/PublicSuffix/BuiltIn.pm'}, "BuiltIn loaded if needed";
