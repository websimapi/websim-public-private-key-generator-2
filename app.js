document.addEventListener('DOMContentLoaded', () => {
    // DOM elements
    const keyTypeSelect = document.getElementById('keyType');
    const rsaKeySizeDiv = document.getElementById('rsaKeySize');
    const ecdsaCurveDiv = document.getElementById('ecdsaCurve');
    const keySizeSelect = document.getElementById('keySize');
    const curveSelect = document.getElementById('curve');
    const generateBtn = document.getElementById('generateBtn');
    const privateKeyTextarea = document.getElementById('privateKey');
    const publicKeyTextarea = document.getElementById('publicKey');
    const copyPrivateBtn = document.getElementById('copyPrivateBtn');
    const copyPublicBtn = document.getElementById('copyPublicBtn');
    const downloadPrivateBtn = document.getElementById('downloadPrivateBtn');
    const downloadPublicBtn = document.getElementById('downloadPublicBtn');
    const statusDiv = document.getElementById('status');

    // Signature elements
    const messageInput = document.getElementById('messageInput');
    const signBtn = document.getElementById('signBtn');
    const verifyBtn = document.getElementById('verifyBtn');
    const clearBtn = document.getElementById('clearBtn');
    const signatureOutput = document.getElementById('signatureOutput');
    const verificationResult = document.getElementById('verificationResult');

    // Toggle between RSA and ECDSA key options
    keyTypeSelect.addEventListener('change', () => {
        const isRSA = keyTypeSelect.value === 'RSA';
        rsaKeySizeDiv.style.display = isRSA ? 'block' : 'none';
        ecdsaCurveDiv.style.display = isRSA ? 'none' : 'block';
    });

    // Current key pair objects for signature operations
    let currentPrivateKey = null;
    let currentPublicKey = null;

    // Generate key pair
    generateBtn.addEventListener('click', async () => {
        try {
            setStatus('Generating keys... This may take a moment.', 'info');
            generateBtn.disabled = true;
            
            const keyType = keyTypeSelect.value;
            let keyPair;
            
            if (keyType === 'RSA') {
                const modulusLength = parseInt(keySizeSelect.value);
                keyPair = await generateRSAKeyPair(modulusLength);
            } else { // ECDSA
                const namedCurve = curveSelect.value;
                keyPair = await generateECDSAKeyPair(namedCurve);
            }
            
            // Display keys
            privateKeyTextarea.value = keyPair.privateKey;
            publicKeyTextarea.value = keyPair.publicKey;
            
            // Store the CryptoKey objects for signing/verification
            currentPrivateKey = keyPair.privateKeyObject;
            currentPublicKey = keyPair.publicKeyObject;
            
            // Clear previous signature data
            clearSignatureData();
            
            setStatus('Key pair generated successfully!', 'success');
        } catch (error) {
            console.error('Error generating key pair:', error);
            setStatus(`Error: ${error.message}`, 'error');
        } finally {
            generateBtn.disabled = false;
        }
    });

    // Copy and download buttons
    copyPrivateBtn.addEventListener('click', () => copyToClipboard(privateKeyTextarea, 'Private key'));
    copyPublicBtn.addEventListener('click', () => copyToClipboard(publicKeyTextarea, 'Public key'));
    downloadPrivateBtn.addEventListener('click', () => downloadKey(privateKeyTextarea.value, `private_key_${getTimestamp()}.pem`));
    downloadPublicBtn.addEventListener('click', () => downloadKey(publicKeyTextarea.value, `public_key_${getTimestamp()}.pem`));

    // Signature functionality
    signBtn.addEventListener('click', async () => {
        try {
            const message = messageInput.value.trim();
            
            if (!message) {
                setVerificationResult('Please enter a message to sign', 'error');
                return;
            }
            
            if (!currentPrivateKey) {
                setVerificationResult('Please generate a key pair first', 'error');
                return;
            }
            
            // Convert message to ArrayBuffer
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            
            // Sign the message
            const algorithm = currentPrivateKey.algorithm.name === 'RSASSA-PKCS1-v1_5' 
                ? 'RSASSA-PKCS1-v1_5' 
                : { 
                    name: 'ECDSA', 
                    hash: { name: 'SHA-256' } 
                };
                
            const signature = await window.crypto.subtle.sign(
                algorithm,
                currentPrivateKey,
                data
            );
            
            // Convert signature to Base64 for display
            const signatureBase64 = arrayBufferToBase64(signature);
            signatureOutput.value = signatureBase64;
            
            setVerificationResult('Message signed successfully', 'success');
        } catch (error) {
            console.error('Signing error:', error);
            setVerificationResult(`Signing failed: ${error.message}`, 'error');
        }
    });
    
    verifyBtn.addEventListener('click', async () => {
        try {
            const message = messageInput.value.trim();
            const signatureBase64 = signatureOutput.value.trim();
            
            if (!message || !signatureBase64) {
                setVerificationResult('Both message and signature are required', 'error');
                return;
            }
            
            if (!currentPublicKey) {
                setVerificationResult('Please generate a key pair first', 'error');
                return;
            }
            
            // Convert message to ArrayBuffer
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            
            // Convert Base64 signature to ArrayBuffer
            const signatureArrayBuffer = base64ToArrayBuffer(signatureBase64);
            
            // Verify the signature
            const algorithm = currentPublicKey.algorithm.name === 'RSASSA-PKCS1-v1_5' 
                ? 'RSASSA-PKCS1-v1_5' 
                : { 
                    name: 'ECDSA', 
                    hash: { name: 'SHA-256' } 
                };
                
            const isValid = await window.crypto.subtle.verify(
                algorithm,
                currentPublicKey,
                signatureArrayBuffer,
                data
            );
            
            if (isValid) {
                setVerificationResult('Signature verified successfully! ', 'success');
            } else {
                setVerificationResult('Signature verification failed! ', 'error');
            }
        } catch (error) {
            console.error('Verification error:', error);
            setVerificationResult(`Verification error: ${error.message}`, 'error');
        }
    });
    
    clearBtn.addEventListener('click', clearSignatureData);
    
    // Helper functions
    async function generateRSAKeyPair(modulusLength) {
        // Generate RSA key pair using Web Crypto API
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
                hash: { name: 'SHA-256' }
            },
            true, // extractable
            ['sign', 'verify']
        );

        // Export private key as PKCS#8
        const privateKeyArrayBuffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const privateKeyBase64 = arrayBufferToBase64(privateKeyArrayBuffer);
        const privateKeyPEM = formatAsPEM(privateKeyBase64, 'PRIVATE KEY');

        // Export public key as SPKI
        const publicKeyArrayBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = arrayBufferToBase64(publicKeyArrayBuffer);
        const publicKeyPEM = formatAsPEM(publicKeyBase64, 'PUBLIC KEY');

        return {
            privateKey: privateKeyPEM,
            publicKey: publicKeyPEM,
            privateKeyObject: keyPair.privateKey,
            publicKeyObject: keyPair.publicKey
        };
    }

    async function generateECDSAKeyPair(namedCurve) {
        // Generate ECDSA key pair using Web Crypto API
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve
            },
            true, // extractable
            ['sign', 'verify']
        );

        // Export private key as PKCS#8
        const privateKeyArrayBuffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const privateKeyBase64 = arrayBufferToBase64(privateKeyArrayBuffer);
        const privateKeyPEM = formatAsPEM(privateKeyBase64, 'EC PRIVATE KEY');

        // Export public key as SPKI
        const publicKeyArrayBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const publicKeyBase64 = arrayBufferToBase64(publicKeyArrayBuffer);
        const publicKeyPEM = formatAsPEM(publicKeyBase64, 'PUBLIC KEY');

        return {
            privateKey: privateKeyPEM,
            publicKey: publicKeyPEM,
            privateKeyObject: keyPair.privateKey,
            publicKeyObject: keyPair.publicKey
        };
    }

    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    function formatAsPEM(base64Data, label) {
        const pemHeader = `-----BEGIN ${label}-----`;
        const pemFooter = `-----END ${label}-----`;
        
        // Wrap the base64 string to 64 characters per line
        let formattedBase64 = '';
        for (let i = 0; i < base64Data.length; i += 64) {
            formattedBase64 += base64Data.slice(i, i + 64) + '\n';
        }
        
        return `${pemHeader}\n${formattedBase64}${pemFooter}`;
    }

    async function copyToClipboard(textElement, keyType) {
        if (!textElement.value) {
            setStatus('Nothing to copy. Generate keys first.', 'error');
            return;
        }
        
        try {
            await navigator.clipboard.writeText(textElement.value);
            setStatus(`${keyType} copied to clipboard!`, 'success');
        } catch (error) {
            console.error('Copy failed:', error);
            setStatus('Failed to copy to clipboard', 'error');
        }
    }

    function downloadKey(keyData, filename) {
        if (!keyData) {
            setStatus('Nothing to download. Generate keys first.', 'error');
            return;
        }
        
        const blob = new Blob([keyData], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
        
        setStatus(`Downloaded ${filename}`, 'success');
    }

    function getTimestamp() {
        const now = new Date();
        return now.toISOString().replace(/[:.]/g, '-');
    }

    function setStatus(message, type) {
        statusDiv.textContent = message;
        statusDiv.className = 'status-message';
        if (type) {
            statusDiv.classList.add(type);
        }
    }

    function base64ToArrayBuffer(base64) {
        const binary = window.atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function clearSignatureData() {
        messageInput.value = '';
        signatureOutput.value = '';
        verificationResult.textContent = '';
        verificationResult.className = 'verification-result';
    }
    
    function setVerificationResult(message, type) {
        verificationResult.textContent = message;
        verificationResult.className = 'verification-result';
        if (type) {
            verificationResult.classList.add(type);
        }
    }
});