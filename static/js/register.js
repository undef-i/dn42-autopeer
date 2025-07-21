window.alert = function (message) {
    Snackbar.show({ pos: 'top-center', text: message, showAction: false, });
};

function nextStep() {
    var nextButton = document.getElementById('nextButton');
    var authTypeContainer = document.getElementById('authTypeContainer');
    var emailVerificationContainer = document.getElementById('emailVerificationContainer');
    var authAuthContainer = document.getElementById('authAuthContainer');
    var verificationCodeInput = document.getElementById('verificationCode');
    var sendVerificationButton = document.getElementById('sendVerificationButton');
    var publicKeyInput = document.getElementById('publicKey');
    var signedTextInput = document.getElementById('signedText');

    if (document.getElementById('ASN').value.trim()) {

        if (authTypeContainer.style.display === 'none') {
            fetchASNInfo();
        } else if (document.getElementById('emailAuth').checked) {
            document.querySelectorAll('#authTypeContainer div input[type="radio"]').forEach(radio => radio.disabled = true);
            emailVerificationContainer.style.display = 'flex';
            sendVerificationButton.style.display = 'inline';
            nextButton.textContent = 'Verify Code';
            nextButton.onclick = function () {
                var verificationCode = verificationCodeInput.value.trim();
                if (verificationCode) {
                    verifyCode(verificationCode);
                } else {
                    alert('Please enter the verification code.');
                }
            }
        } else if (document.getElementById('authAuth').checked) {
            document.querySelectorAll('#authTypeContainer div input[type="radio"]').forEach(radio => radio.disabled = true);
            authAuthContainer.style.display = 'block';

            const authInfoText = document.querySelector('#authInfo').textContent;
            const pgpFingerprintMatch = authInfoText.match(/pgp-fingerprint\s+([^\s)]+)\)/);
            const pgpFingerprint = pgpFingerprintMatch ? pgpFingerprintMatch[1] : null;
            const sshRsaMatch = authInfoText.match(/ssh-rsa\s+([^\s)]+)/);
            const sshRsa = sshRsaMatch ? sshRsaMatch[1] : null;
            const sshDssMatch = authInfoText.match(/ssh-dss\s+([^\s)]+)/);
            const sshDss = sshDssMatch ? sshDssMatch[1] : null;
            const sshEd25519Match = authInfoText.match(/ssh-ed25519\s+([^\s)]+)/);
            const sshEd25519 = sshEd25519Match ? sshEd25519Match[1] : null;
            const sshEcdsaMatch = authInfoText.match(/ecdsa-sha2-nistp256\s+([^\s)]+)/);
            const sshEcdsa = sshEcdsaMatch ? sshEcdsaMatch[1] : null;

            if (pgpFingerprint) {
                document.querySelector('label[for="theCode"]').parentElement.style.display = 'block';
                document.getElementById('theCode').value = `gpg --armor --export --fingerprint ${pgpFingerprint}\recho -n "U2FsdGVkX19UqLcfZVBTJOiez/JeD1SWIfDI1pFGQaQ=" | gpg --clearsign --detach-sign -u ${pgpFingerprint}`;
                nextButton.textContent = 'Send PGP Information';
                nextButton.onclick = function () {
                    var ASNInput = document.getElementById('ASN').value;
                    var publicKey = publicKeyInput.value.trim();
                    var signedText = signedTextInput.value.trim();
                    if (ASNInput && publicKey && signedText) {
                        var formData = new FormData();
                        formData.append('ASN', ASNInput);
                        formData.append('public_key', publicKey);
                        formData.append('signed_text', signedText);

                        fetch('/verify_gpg_signature', {
                            method: 'POST',
                            body: formData
                        }).then(response => {
                            if (response.ok) {
                                window.location.href = '/dashboard';
                            } else {
                                return response.text();
                            }
                        })
                    } else {
                        alert('Please fill in all fields.');
                    }
                };
            } else if (sshRsa || sshDss || sshEd25519 || sshEcdsa) {
                let keyType = '';
                if (sshRsa) {
                    keyType = 'rsa';
                    document.getElementById('theCode').value = `echo -n "U2FsdGVkX19UqLcfZVBTJOiez/JeD1SWIfDI1pFGQaQ=" | ssh-keygen -Y sign -n dn42ap -f ~/.ssh/id_rsa`;
                } else if (sshDss) {
                    keyType = 'dss';
                    document.getElementById('theCode').value = `echo -n "U2FsdGVkX19UqLcfZVBTJOiez/JeD1SWIfDI1pFGQaQ=" | ssh-keygen -Y sign -n dn42ap -f ~/.ssh/id_dsa`;
                } else if (sshEd25519) {
                    keyType = 'ed25519';
                    document.getElementById('theCode').value = `echo -n "U2FsdGVkX19UqLcfZVBTJOiez/JeD1SWIfDI1pFGQaQ=" | ssh-keygen -Y sign -n dn42ap -f ~/.ssh/id_ed25519`;
                } else if (sshEcdsa) {
                    keyType = 'ecdsa';
                    document.getElementById('theCode').value = `echo -n "U2FsdGVkX19UqLcfZVBTJOiez/JeD1SWIfDI1pFGQaQ=" | ssh-keygen -Y sign -n dn42ap -f ~/.ssh/id_ecdsa`;
                }
                document.querySelector('label[for="theCode"]').parentElement.style.display = 'block';
                nextButton.textContent = `Send ${keyType.toUpperCase()} Information`;
                nextButton.onclick = function () {
                    var ASNInput = document.getElementById('ASN').value;
                    var publicKey = publicKeyInput.value.trim();
                    var signedText = signedTextInput.value.trim();
                    if (ASNInput && publicKey && signedText) {
                        var formData = new FormData();
                        formData.append('ASN', ASNInput);
                        formData.append('public_key', publicKey);
                        formData.append('signed_text', signedText);

                        fetch(`/verify_ssh_signature`, {
                            method: 'POST',
                            body: formData
                        }).then(response => {
                            if (response.ok) {
                                window.location.href = '/dashboard';
                            } else {
                                return response.text();
                            }
                        })
                    } else {
                        alert('Please fill in all fields.');
                    }
                };
            } else {
                document.querySelector('label[for="theCode"]').parentElement.style.display = 'none';
            }

            document.getElementById('theCode').addEventListener('click', () => navigator.clipboard.writeText(document.getElementById('theCode').value));

        }
    } else {
        alert('Please enter an ASN number.');
    }
}




function fetchASNInfo() {
    var ASNInput = document.getElementById('ASN').value;
    if (Number(ASNInput)!=ASNInput){
        return 
    }

    document.getElementById('spinner').style.display = "inline-block";

    fetch('/api/dn42/info?ASN=' + ASNInput).then(response => response.json()).then(data => {
        console.log(data)
        if (data['e-mail']) {
            document.getElementById('emailAddress').textContent = ' (' + data['e-mail'] + ')';
            document.getElementById('authTypeContainer').style.display = 'flex';
            document.getElementById('emailAuth').style.display = 'inline';
            document.getElementById('ASN').disabled = true;
        } else {
            document.getElementById('emailAuth').style.display = 'none';
            document.querySelectorAll('label[for="emailAuth"]').forEach(label => {
                label.style.display = 'none';
            });

        }
        if (data['auth']) {
            document.getElementById('authInfo').textContent = ' (' + data['auth'] + ')';
            document.getElementById('authTypeContainer').style.display = 'flex';
            document.getElementById('authAuth').style.display = 'inline';
            document.getElementById('ASN').disabled = true;
        } else {
            document.getElementById('authAuth').style.display = 'none';
            document.querySelectorAll('label[for="authAuth"]').forEach(label => {
                label.style.display = 'none';
            });
        }

    }).
        catch(error => console.error('Error:', error)).
        finally(() => {
            document.getElementById('spinner').style.display = "none";
        });
}

function sendVerificationCode() {
    var ASNInput = document.getElementById('ASN').value;
    var sendVerificationButton = document.getElementById('sendVerificationButton');

    if (ASNInput) {
        var formData = new FormData();
        formData.append('ASN', ASNInput);
        sendVerificationButton.disabled = true;

        fetch('/send_verification_code', {
            method: 'POST',
            body: formData
        }).then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text();
        }).then(data => {
            alert(data);

            var secondsLeft = 60;
            var countdownInterval = setInterval(function () {
                secondsLeft--;
                sendVerificationButton.textContent = "Resend Code (" + secondsLeft + "s)";
                if (secondsLeft <= 0) {
                    clearInterval(countdownInterval);
                    sendVerificationButton.textContent = "Resend Code";
                    sendVerificationButton.disabled = false;
                }
            }, 1000);

        }).catch(error => {
            sendVerificationButton.textContent = "Resend Code";
            sendVerificationButton.disabled = false;
            alert('Failed to send verification code: ' + error.message);
        });
    }
}




function verifyCode(code) {
    var ASNInput = document.getElementById('ASN').value;
    var formData = new FormData();
    formData.append('ASN', ASNInput);
    formData.append('code', code);
    fetch('/verify_code', {
        method: 'POST',
        body: formData
    }).then(response => {
        if (response.ok) {
            window.location.href = '/dashboard';
        } else {
            return response.text();
        }
    }).then(data => {
        if (data) {
            alert(data);
        }
    });
}
