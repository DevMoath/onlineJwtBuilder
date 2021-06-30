function addMinutes (date, minutes) {
    return new Date(date.getTime() + minutes * 60000);
}

Array.prototype.clear = function() {
    while (this.length > 0) {
        this.pop();
    }
};

function createKey (charCount) {
    let key = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < charCount; i++) {
        key += possible.charAt(Math.floor(Math.random() * possible.length));
    }

    return key;
}

var masterViewModel = function(standardClaims, additionalClaims) {
    var self = this;

    self.standardClaims = standardClaims;
    self.additionalClaims = ko.observableArray(additionalClaims);

    self.key = ko.observable('');
    self.createdJwt = ko.observable('');

    self.isBase64Encoding = ko.observable(false);

    self.selectedAlgorithm = ko.observable('HS256');
    self.algorithms = ko.observableArray(['HS256', 'HS384', 'HS512']);

    self.keyLength = ko.computed(function() {
        return self.key().length;
    });

    self.generatedClaimSet = ko.computed(function() {
        var iat = new Date(this.standardClaims.issuedAt()).getTime();
        var exp = new Date(this.standardClaims.expiration()).getTime();
        var sub = this.standardClaims.subject();

        if (!isNaN(sub) && !sub.startsWith('0')) {
            sub = parseInt(sub);
        }

        var claimSet = {
            iss: this.standardClaims.issuer(),
            iat: Math.floor(iat / 1000),
            exp: Math.floor(exp / 1000),
            aud: this.standardClaims.audience(),
            sub: sub,
        };

        var claims = this.additionalClaims();

        for (var i = 0; i < claims.length; i++) {
            var claimType = claims[i].claimType();
            var value = claims[i].value();

            if (!claimType || !value) continue;

            if (!claimSet[claimType]) {
                claimSet[claimType] = value;
            } else {
                var current = claimSet[claimType];
                if ($.isArray(current)) {
                    current.push(value);
                } else {
                    var newArray = [];
                    newArray.push(current);
                    newArray.push(value);
                    claimSet[claimType] = newArray;
                }
            }
        }

        return claimSet;
    }, self);

    self.generatedClaimSetDisplay = ko.computed(function() {
        return JSON.stringify(this.generatedClaimSet(), null, 4);
    }, this);

    self.clearCreatedJwt = ko.computed(function() {
        self.generatedClaimSet();
        self.key();
        self.createdJwt('');
        self.isBase64Encoding();
        self.selectedAlgorithm();
    }, self);

    self.toggleBase64 = function() {
        var current = self.isBase64Encoding();
        self.isBase64Encoding(!current);
        return false;
    };

    self.toggleAlgorithm = function(item) {
        self.selectedAlgorithm(item);
    };

    self.issuedAtSetNow = function() {
        this.standardClaims.issuedAt(new Date().toISOString());
    };

    self.expirationSetNow = function() {
        this.standardClaims.expiration(new Date().toISOString());
    };

    self.expirationSetTwentyMinutes = function() {
        var now = new Date();
        var later = addMinutes(now, 20);
        this.standardClaims.expiration(later.toISOString());
    };

    self.expirationSetOneYear = function() {
        var now = new Date();
        var later = addMinutes(now, 365 * 24 * 60);
        this.standardClaims.expiration(later.toISOString());
    };

    self.clearAllAdditionalClaims = function() {
        while (this.additionalClaims().length > 0) {
            this.additionalClaims.pop();
        }
    };

    self.addOneAdditionalClaim = function() {
        this.additionalClaims.push(new claimViewModel('', ''));
    };

    self.addEmailAdditionalClaim = function() {
        this.additionalClaims.push(new claimViewModel('Email', 'bee@example.com'));
    };

    self.addNameNetAdditionalClaim = function() {
        this.additionalClaims.push(
            new claimViewModel('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', 'jrocket'),
        );
    };

    self.addRoleNetAdditionalClaim = function() {
        this.additionalClaims.push(
            new claimViewModel('http://schemas.microsoft.com/ws/2008/06/identity/claims/role', 'Manager'),
        );
    };

    self.addEmailNetAdditionalClaim = function() {
        this.additionalClaims.push(
            new claimViewModel('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email', 'bee@example.com'),
        );
    };

    self.removeClaim = function(claim) {
        self.additionalClaims.remove(claim);
    };

    self.generateSymmetricKey = function(charCount) {
        self.key(createKey(charCount));
        return false;
    };

    self.createJwt = function() {
        var request = {
            claims: this.generatedClaimSet(),
            key: this.key(),
            alg: self.selectedAlgorithm(),
        };

        var data = ko.toJSON(request);

        $.ajax({
            type: 'POST',
            url: '/tokens',
            data: data,
            contentType: 'application/json;charset=utf8',
            success: self.onTokenSuccess,
            error: self.onTokenError,
        });
    };

    self.onTokenSuccess = function(data, status) {
        var token = data.token;
        if (self.isBase64Encoding()) {
            token = base64.encode(token);
        }

        self.createdJwt(token);
    };

    self.onTokenError = function(error) {
        self.createdJwt(error.responseText);
    };

    self.noop = function() {};

    self.warnings = ko.computed(function() {
        var warnings = [];

        var dt = new Date(this.standardClaims.issuedAt());
        if (isNaN(dt)) {
            warnings.push(
                'IssuedAt is not a valid <a href="http://www.w3.org/TR/NOTE-datetime">W3C date/time</a>. Must be formatted as: YYYY-MM-DDThh:mm:ssZ',
            );
        }

        dt = new Date(this.standardClaims.expiration());
        if (isNaN(dt)) {
            warnings.push(
                'Expiration  is not a valid <a href="http://www.w3.org/TR/NOTE-datetime">W3C date/time</a>. Must be formatted as: YYYY-MM-DDThh:mm:ssZ',
            );
        }

        return warnings;
    }, self);
};

var standardClaimsViewModel = function(issuer, issuedAt, expiration, audience, subject) {
    var self = this;

    self.issuer = ko.observable(issuer);
    self.issuedAt = ko.observable(issuedAt);
    self.expiration = ko.observable(expiration);
    self.audience = ko.observable(audience);
    self.subject = ko.observable(subject);
};

var createMaster = function() {
    var standardClaims = new standardClaimsViewModel(
        'Online JWT Builder',
        '2014-07-14T08:30Z',
        '2014-07-16T19:20Z',
        'www.example.com',
        'jrocket@example.com',
    );

    var additionalClaims = [
        new claimViewModel('GivenName', 'Johnny'),
        new claimViewModel('Surname', 'Rocket'),
        new claimViewModel('Email', 'jrocket@example.com'),
        new claimViewModel('Role', 'Manager'),
        new claimViewModel('Role', 'Project Administrator'),
    ];

    var master = new masterViewModel(standardClaims, additionalClaims);

    return master;
};

var claimViewModel = function(claimType, value) {
    var self = this;

    self.claimType = ko.observable(claimType);
    self.value = ko.observable(value);
};

window.onload = function() {
    $(function() {
        const copyButton = document.getElementById('copy-button');

        copyButton.addEventListener('click', function() {
            const createdJwt = document.getElementById('created-jwt');
            const copyText = document.getElementById('hidden_input');

            copyText.value = createdJwt.innerText;

            copyText.select();
            copyText.setSelectionRange(0, 99999);

            document.execCommand('copy');

            copyText.value = '';

            copyButton.innerText = 'Copied';

            setTimeout(function() {
                copyButton.innerText = 'Copy JWT to Clipboard';
            }, 3000);
        });

        const viewModel = createMaster();
        ko.applyBindings(viewModel);

        viewModel.key('qwertyuiopasdfghjklzxcvbnm123456');
        viewModel.issuedAtSetNow();
        viewModel.expirationSetOneYear();

        $('a').on('click', function(event) {
            const href = event.currentTarget.href;
            if (href.indexOf('#') === href.length - 1) {
                event.preventDefault();
            }
        });
    });
};

/*
 * Copyright (c) 2010 Nick Galbreath
 * http://code.google.com/p/stringencoders/source/browse/#svn/trunk/javascript
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/* base64 encode/decode compatible with window.btoa/atob
 *
 * window.atob/btoa is a Firefox extension to convert binary data (the "b")
 * to base64 (ascii, the "a").
 *
 * It is also found in Safari and Chrome.  It is not available in IE.
 *
 * if (!window.btoa) window.btoa = base64.encode
 * if (!window.atob) window.atob = base64.decode
 *
 * The original spec's for atob/btoa are a bit lacking
 * https://developer.mozilla.org/en/DOM/window.atob
 * https://developer.mozilla.org/en/DOM/window.btoa
 *
 * window.btoa and base64.encode takes a string where charCodeAt is [0,255]
 * If any character is not [0,255], then an exception is thrown.
 *
 * window.atob and base64.decode take a base64-encoded string
 * If the input length is not a multiple of 4, or contains invalid characters
 *   then an exception is thrown.
 */
base64 = {};
base64.PADCHAR = '=';
base64.ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
base64.getbyte64 = function(s, i) {
    // This is oddly fast, except on Chrome/V8.
    //  Minimal or no improvement in performance by using a
    //   object with properties mapping chars to value (eg. 'A': 0)
    var idx = base64.ALPHA.indexOf(s.charAt(i));
    if (idx == -1) {
        throw 'Cannot decode base64';
    }
    return idx;
};

base64.decode = function(s) {
    // convert to string
    s = '' + s;
    var getbyte64 = base64.getbyte64;
    var pads, i, b10;
    var imax = s.length;
    if (imax == 0) {
        return s;
    }

    if (imax % 4 != 0) {
        throw 'Cannot decode base64';
    }

    pads = 0;
    if (s.charAt(imax - 1) == base64.PADCHAR) {
        pads = 1;
        if (s.charAt(imax - 2) == base64.PADCHAR) {
            pads = 2;
        }
        // either way, we want to ignore this last block
        imax -= 4;
    }

    var x = [];
    for (i = 0; i < imax; i += 4) {
        b10 = (getbyte64(s, i) << 18) | (getbyte64(s, i + 1) << 12) | (getbyte64(s, i + 2) << 6) | getbyte64(s, i + 3);
        x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 0xff, b10 & 0xff));
    }

    switch (pads) {
        case 1:
            b10 = (getbyte64(s, i) << 18) | (getbyte64(s, i + 1) << 12) | (getbyte64(s, i + 2) << 6);
            x.push(String.fromCharCode(b10 >> 16, (b10 >> 8) & 0xff));
            break;
        case 2:
            b10 = (getbyte64(s, i) << 18) | (getbyte64(s, i + 1) << 12);
            x.push(String.fromCharCode(b10 >> 16));
            break;
    }
    return x.join('');
};

base64.getbyte = function(s, i) {
    var x = s.charCodeAt(i);
    if (x > 255) {
        throw 'INVALID_CHARACTER_ERR: DOM Exception 5';
    }
    return x;
};

base64.encode = function(s) {
    if (arguments.length != 1) {
        throw 'SyntaxError: Not enough arguments';
    }
    var padchar = base64.PADCHAR;
    var alpha = base64.ALPHA;
    var getbyte = base64.getbyte;

    var i, b10;
    var x = [];

    // convert to string
    s = '' + s;

    var imax = s.length - (s.length % 3);

    if (s.length == 0) {
        return s;
    }
    for (i = 0; i < imax; i += 3) {
        b10 = (getbyte(s, i) << 16) | (getbyte(s, i + 1) << 8) | getbyte(s, i + 2);
        x.push(alpha.charAt(b10 >> 18));
        x.push(alpha.charAt((b10 >> 12) & 0x3f));
        x.push(alpha.charAt((b10 >> 6) & 0x3f));
        x.push(alpha.charAt(b10 & 0x3f));
    }
    switch (s.length - imax) {
        case 1:
            b10 = getbyte(s, i) << 16;
            x.push(alpha.charAt(b10 >> 18) + alpha.charAt((b10 >> 12) & 0x3f) + padchar + padchar);
            break;
        case 2:
            b10 = (getbyte(s, i) << 16) | (getbyte(s, i + 1) << 8);
            x.push(
                alpha.charAt(b10 >> 18) + alpha.charAt((b10 >> 12) & 0x3f) + alpha.charAt((b10 >> 6) & 0x3f) + padchar,
            );
            break;
    }
    return x.join('');
};
