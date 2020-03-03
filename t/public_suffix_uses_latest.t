use strict;
use warnings;
use FindBin;

use Test::More;

plan tests => 3;

{
    no warnings qw(once redefine);
    $INC{'IO/Socket/SSL/PublicSuffix/Latest.pm'} = __FILE__;
    *IO::Socket::SSL::PublicSuffix::Latest::get_tree = sub { return { 'fake_tree' => 1 }; };
    use warnings qw(once redefine);
}

require IO::Socket::SSL::PublicSuffix;

ok !$INC{'IO/Socket/SSL/PublicSuffix/BuiltIn.pm'}, "BuiltIn not loaded until requested";
my $ps = IO::Socket::SSL::PublicSuffix->default( min_suffix => 0 );
ok !$INC{'IO/Socket/SSL/PublicSuffix/BuiltIn.pm'}, "BuiltIn was not loaded beause Latest was available.";

is( $ps->{'tree'}{'fake_tree'}, 1, "...and our test data was loaded" );
