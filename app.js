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

    // Toggle between RSA and ECDSA key options
    keyTypeSelect.addEventListener('change', () => {
        const isRSA = keyTypeSelect.value === 'RSA';
        rsaKeySizeDiv.style.display = isRSA ? 'block' : 'none';
        ecdsaCurveDiv.style.display = isRSA ? 'none' : 'block';
    });

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
            publicKey: publicKeyPEM
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
            publicKey: publicKeyPEM
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
});

