document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const encryptTabBtn = document.getElementById('encrypt-tab-btn');
    const decryptTabBtn = document.getElementById('decrypt-tab-btn');
    const encryptPanel = document.getElementById('encrypt-panel');
    const decryptPanel = document.getElementById('decrypt-panel');
    const encryptDropZone = document.getElementById('encrypt-drop-zone');
    const encryptFileInput = document.getElementById('encrypt-file-input');
    const encryptFileName = document.getElementById('encrypt-file-name');
    const encryptBtn = document.getElementById('encrypt-btn');
    const encryptPasswordInput = document.getElementById('encrypt-password');
    const encryptPasswordConfirmInput = document.getElementById('encrypt-password-confirm');
    const decryptDropZone = document.getElementById('decrypt-drop-zone');
    const decryptFileInput = document.getElementById('decrypt-file-input');
    const decryptFileName = document.getElementById('decrypt-file-name');
    const decryptBtn = document.getElementById('decrypt-btn');
    const decryptPasswordInput = document.getElementById('decrypt-password');
    const statusArea = document.getElementById('status-area');

    let encryptFile = null;
    let decryptFile = null;

    // --- Fun aliases for encrypted filenames ---
    const funAliases = [
        'IronMan', 'CaptainAmerica', 'Thor', 'Hulk', 'BlackWidow', 'Hawkeye',
        'SpiderMan', 'Wolverine', 'Deadpool', 'WonderWoman', 'Superman', 'Batman',
        'ScoobyDoo', 'Shaggy', 'Velma', 'Daphne', 'Fred', 'BugsBunny', 'DaffyDuck',
        'Pikachu', 'Charizard', 'MickeyMouse', 'Goofy', 'DonaldDuck', 'OptimusPrime',
        'BlackPanther', 'DoctorStrange', 'Groot', 'RocketRaccoon', 'Yoda', 'DarthVader'
    ];

    function getRandomAlias() {
        const randomIndex = Math.floor(Math.random() * funAliases.length);
        return funAliases[randomIndex];
    }

    // --- Crypto Constants ---
    const SALT_SIZE = 16; // 128 bits
    const IV_SIZE = 12; // 96 bits for GCM
    const PBKDF2_ITERATIONS = 310000; // OWASP recommendation

    // --- UI Logic ---
    encryptTabBtn.addEventListener('click', () => switchTab('encrypt'));
    decryptTabBtn.addEventListener('click', () => switchTab('decrypt'));

    function switchTab(tab) {
        if (tab === 'encrypt') {
            encryptTabBtn.classList.add('active');
            decryptTabBtn.classList.remove('active');
            encryptPanel.classList.remove('hidden');
            decryptPanel.classList.add('hidden');
        } else {
            encryptTabBtn.classList.remove('active');
            decryptTabBtn.classList.add('active');
            encryptPanel.classList.add('hidden');
            decryptPanel.classList.remove('hidden');
        }
        clearStatus();
    }

    function setupDropZone(zone, input, fileVarSetter, nameDisplay, buttonValidator) {
        zone.addEventListener('click', () => input.click());
        zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
        zone.addEventListener('dragleave', (e) => { e.preventDefault(); zone.classList.remove('dragover'); });
        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                const file = e.dataTransfer.files[0];
                fileVarSetter(file);
                nameDisplay.textContent = file.name;
                buttonValidator();
            }
        });
        input.addEventListener('change', (e) => {
            if (e.target.files.length) {
                const file = e.target.files[0];
                fileVarSetter(file);
                nameDisplay.textContent = file.name;
                buttonValidator();
            }
        });
    }

    setupDropZone(encryptDropZone, encryptFileInput, (f) => { encryptFile = f; }, encryptFileName, validateEncryptButton);
    setupDropZone(decryptDropZone, decryptFileInput, (f) => { decryptFile = f; }, decryptFileName, validateDecryptButton);

    encryptPasswordInput.addEventListener('input', validateEncryptButton);
    encryptPasswordConfirmInput.addEventListener('input', validateEncryptButton);
    decryptPasswordInput.addEventListener('input', validateDecryptButton);

    function validateEncryptButton() {
        const passwordsMatch = encryptPasswordInput.value === encryptPasswordConfirmInput.value;
        encryptBtn.disabled = !(encryptFile && encryptPasswordInput.value.length > 0 && passwordsMatch);
    }

    function validateDecryptButton() {
        decryptBtn.disabled = !(decryptFile && decryptPasswordInput.value.length > 0);
    }

    encryptBtn.addEventListener('click', handleEncrypt);
    decryptBtn.addEventListener('click', handleDecrypt);

    // --- Core Logic ---
    async function handleEncrypt() {
        if (!encryptFile) {
            showError('Please select a file to encrypt.');
            return;
        }
        const password = encryptPasswordInput.value;
        const passwordConfirm = encryptPasswordConfirmInput.value;

        if (password.length < 8) {
            showError('Password must be at least 8 characters long.');
            return;
        }
        if (password !== passwordConfirm) {
            showError('Passwords do not match. Please re-enter.');
            return;
        }

        showLoading('Encrypting file...');

        try {
            const fileBuffer = await encryptFile.arrayBuffer();
            const encryptedBlob = await encryptWithPassword(fileBuffer, password, encryptFile.name);
            showSuccess('File encrypted successfully! Your download should begin automatically.');
            
            const encryptedFilename = getRandomAlias() + '.encrypted';

            createDownloadLink(encryptedBlob, encryptedFilename, 'Encrypted File');
        } catch (error) {
            console.error('Encryption error:', error);
            showError(`An error occurred during encryption: ${error.message}`);
        }
    }

    async function handleDecrypt() {
        if (!decryptFile) {
            showError('Please select a file to decrypt.');
            return;
        }
        const password = decryptPasswordInput.value;
        if (!password) {
            showError('Please enter the password.');
            return;
        }

        showLoading('Decrypting file...');

        try {
            const encryptedBuffer = await decryptFile.arrayBuffer();
            const { decryptedData, originalFilename } = await decryptWithPassword(encryptedBuffer, password);

            const decryptedBlob = new Blob([decryptedData]);
            showSuccess('File decrypted successfully! Your download should begin automatically.');
            createDownloadLink(decryptedBlob, originalFilename, 'Decrypted File');

        } catch (error) {
            console.error('Decryption error:', error);
            showError(`Decryption failed. Check password or file integrity. Error: ${error.message}`);
        }
    }

    // --- Cryptographic Functions ---
    async function getKeyFromPassword(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
        return window.crypto.subtle.deriveKey({
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }

    async function encryptWithPassword(data, password, originalFilename) {
        const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
        const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));
        const key = await getKeyFromPassword(password, salt);

        const filenameBytes = new TextEncoder().encode(originalFilename);
        const filenameLengthBuffer = new ArrayBuffer(2);
        new DataView(filenameLengthBuffer).setUint16(0, filenameBytes.length, false);

        const plaintext = new Uint8Array(2 + filenameBytes.length + data.byteLength);
        plaintext.set(new Uint8Array(filenameLengthBuffer), 0);
        plaintext.set(filenameBytes, 2);
        plaintext.set(new Uint8Array(data), 2 + filenameBytes.length);

        const encryptedContent = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, plaintext);

        const result = new Uint8Array(SALT_SIZE + IV_SIZE + encryptedContent.byteLength);
        result.set(salt, 0);
        result.set(iv, SALT_SIZE);
        result.set(new Uint8Array(encryptedContent), SALT_SIZE + IV_SIZE);

        return new Blob([result]);
    }

    async function decryptWithPassword(encryptedData, password) {
        const encryptedBytes = new Uint8Array(encryptedData);
        const salt = encryptedBytes.slice(0, SALT_SIZE);
        const iv = encryptedBytes.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
        const data = encryptedBytes.slice(SALT_SIZE + IV_SIZE);

        const key = await getKeyFromPassword(password, salt);
        const decryptedPayload = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
        
        const decryptedBytes = new Uint8Array(decryptedPayload);
        const filenameLength = new DataView(decryptedBytes.buffer, 0, 2).getUint16(0, false);
        const filenameBytes = decryptedBytes.slice(2, 2 + filenameLength);
        const originalFilename = new TextDecoder().decode(filenameBytes);
        
        // BUG FIX: The slice method on a TypedArray creates a *view* on the original buffer.
        // We need to create a new buffer that contains only the file data.
        // The original code was returning the entire buffer, including the filename data.
        const originalFileBytes = decryptedBytes.slice(2 + filenameLength);

        return { decryptedData: originalFileBytes, originalFilename };
    }

    // --- UI Helper Functions ---
    function showLoading(message) {
        statusArea.innerHTML = `<div class="flex flex-col items-center justify-center"><div class="loader mb-2"></div><p>${message}</p></div>`;
    }

    function showSuccess(message) {
        statusArea.innerHTML = `<div class="bg-green-100 border-l-4 border-green-500 text-green-700 p-4" role="alert"><p class="font-bold">Success</p><p>${message}</p></div>`;
    }

    function showError(message) {
        statusArea.innerHTML = `<div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4" role="alert"><p class="font-bold">Error</p><p>${message}</p></div>`;
    }

    function createDownloadLink(blob, fileName, label) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName;

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        setTimeout(() => URL.revokeObjectURL(url), 100);

        let container = document.getElementById('download-links');
        if (!container) {
            container = document.createElement('div');
            container.id = 'download-links';
            container.className = 'mt-4 space-y-2';
            statusArea.appendChild(container);
        }
        const downloadAgainLink = document.createElement('a');
        downloadAgainLink.href = url;
        downloadAgainLink.download = fileName;
        downloadAgainLink.textContent = `Download ${label} Again`;
        downloadAgainLink.className = 'block w-full text-center mt-2 bg-gray-600 text-white font-semibold py-2 px-4 rounded-lg shadow-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500';

        container.innerHTML = ''; 
        container.appendChild(downloadAgainLink);
    }

    function clearStatus() {
        statusArea.innerHTML = '';
    }
});

