vcl 4.1;

import std;

backend projectname {
    .host = "127.0.0.1";
    .port = "8080";
    .max_connections = 100;
    .connect_timeout        = 5s;
    .first_byte_timeout     = 90s;
    .between_bytes_timeout  = 2s;
}

acl purge {
    "localhost";
    "127.0.0.1";
    "::1";
}

sub vcl_recv {
    if (req.url ~ "^/\.well-known/acme-challenge/") {
        set req.backend_hint = projectname;
        return(pipe);
    }
    

    # Forward client's IP to the backend
    if (req.restarts == 0) {
        if (req.http.X-Real-IP) {
            set req.http.X-Forwarded-For = req.http.X-Real-IP;
        } else if (req.http.X-Forwarded-For) {
            set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
        } else {
            set req.http.X-Forwarded-For = client.ip;
        }
    }


    set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");
    unset req.http.proxy;
    set req.url = std.querysort(req.url);
    set req.url = regsub(req.url, "\?$", "");
    set req.http.Surrogate-Capability = "key=ESI/1.0";

    if (std.healthy(req.backend_hint)) {
        set req.grace = 10s;
    }

    if (!req.http.X-Forwarded-Proto) {
        if(std.port(server.ip) == 443) {
            set req.http.X-Forwarded-Proto = "https";
        } else {
            set req.http.X-Forwarded-Proto = "https";
        }
    }

    # === STATIC FILES ===
    # Properly handle different encoding types
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|jpeg|png|gif|gz|tgz|bz2|tbz|mp3|ogg|swf)$") {
            # No point in compressing these
            unset req.http.Accept-Encoding;
        } elseif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } elseif (req.http.Accept-Encoding ~ "deflate") {
            set req.http.Accept-Encoding = "deflate";
        } else {
            # unknown algorithm (aka crappy browser)
            unset req.http.Accept-Encoding;
        }
    }

    if (req.http.Upgrade ~ "(?i)websocket") {
        return (pipe);
    }

    if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
        set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
        set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
        set req.url = regsub(req.url, "\?&", "?");
        set req.url = regsub(req.url, "\?$", "");
    }

    if (req.method == "PURGE") {
        if (!client.ip ~ purge) {
            return (synth(405, client.ip + " is not allowed to send PURGE requests."));
        }
        return (purge);
    }

    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "PATCH" &&
        req.method != "DELETE") {
        return (pipe);
    }

    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|ogg|ogm|opus|otf|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        unset req.http.Cookie;
        return(hash);
    }

    set req.http.Cookie = regsuball(req.http.Cookie, "(__utm|_ga|_opt)[a-z_]*=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "(__)?hs[a-z_\-]+=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "hubspotutk=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "_hj[a-zA-Z]+=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "(NID|DSID|__gads|GED_PLAYLIST_ACTIVITY|ACLK_DATA|ANID|AID|IDE|TAID|_gcl_[a-z]*|FLC|RUL|PAIDCONTENT|1P_JAR|Conversion|VISITOR_INFO1[a-z_]*)=[^;]+(; )?", "");
    set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");

    if (req.http.cookie ~ "^\s*$") {
        unset req.http.cookie;
    }
}

sub vcl_pipe {
    if (req.backend_hint == projectname) {
        set req.http.Connection = "close";
        return(pipe);
    }
}

sub vcl_hash {
    hash_data(req.http.X-Forwarded-Proto);
}

sub vcl_backend_response {
    if (bereq.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|ogg|ogm|opus|otf|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
        unset beresp.http.Set-Cookie;
        set beresp.ttl = 1d;
    }

    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
    }

    # Unset the "pragma" header (suggested)
    unset beresp.http.Pragma;

    # Unset the "vary" header (suggested)
    unset beresp.http.Vary;

    set beresp.ttl = 10s;
    set beresp.grace = 2h;
}