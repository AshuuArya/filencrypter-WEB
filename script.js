document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements ---
    const encryptTabBtn = document.getElementById('encrypt-tab-btn');
    const decryptTabBtn = document.getElementById('decrypt-tab-btn');
    const encryptPanel = document.getElementById('encrypt-panel');
    const decryptPanel = document.getElementById('decrypt-panel');

    // Encrypt Panel Elements
    const encryptDropZone = document.getElementById('encrypt-drop-zone');
    const encryptFileInput = document.getElementById('encrypt-file-input');
    const encryptFileName = document.getElementById('encrypt-file-name');
    const encryptBtn = document.getElementById('encrypt-btn');
    const encryptPasswordInput = document.getElementById('encrypt-password');

    // Decrypt Panel Elements
    const decryptDropZone = document.getElementById('decrypt-drop-zone');
    const decryptFileInput = document.getElementById('decrypt-file-input');
    const decryptFileName = document.getElementById('decrypt-file-name');
    const decryptBtn = document.getElementById('decrypt-btn');
    const decryptPasswordInput = document.getElementById('decrypt-password');

    // Status Area
    const statusArea = document.getElementById('status-area');
    
    let encryptFile = null;
    let decryptFile = null;

    // --- Crypto Constants (matching the desktop app for compatibility) ---
    const SALT_SIZE = 16;       // 128 bits
    const IV_SIZE = 12;         // 96 bits for GCM
    const PBKDF2_ITERATIONS = 600000; // High iteration count for security

    // --- UI Logic ---

    // Tab switching
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
    
    // --- File Handling & Drag/Drop ---
    function setupDropZone(zone, input, fileVarSetter, nameDisplay, buttonValidator) {
        zone.addEventListener('click', () => input.click());
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });
        zone.addEventListener('dragleave', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
        });
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
    decryptPasswordInput.addEventListener('input', validateDecryptButton);

    function validateEncryptButton() {
        encryptBtn.disabled = !(encryptFile && encryptPasswordInput.value.length > 0);
    }

    function validateDecryptButton() {
        decryptBtn.disabled = !(decryptFile && decryptPasswordInput.value.length > 0);
    }

    // --- Button Click Handlers ---
    encryptBtn.addEventListener('click', handleEncrypt);
    decryptBtn.addEventListener('click', handleDecrypt);

    // --- Core Logic ---
    async function handleEncrypt() {
        if (!encryptFile) {
            showError('Please select a file to encrypt.');
            return;
        }
        const password = encryptPasswordInput.value;
        if (password.length < 8) {
            showError('Password must be at least 8 characters long.');
            return;
        }

        showLoading('Encrypting file...');
        
        try {
            const fileBuffer = await encryptFile.arrayBuffer();
            const encryptedBlob = await encryptWithPassword(fileBuffer, password, encryptFile.name);
            showSuccess('File encrypted successfully! Your download should begin automatically.');
            createDownloadLink(encryptedBlob, `${encryptFile.name}.encrypted`, 'Encrypted File');
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
            const { decryptedBuffer, originalFilename } = await decryptWithPassword(encryptedBuffer, password);
            
            const decryptedBlob = new Blob([decryptedBuffer]);
            showSuccess('File decrypted successfully! Your download should begin automatically.');
            createDownloadLink(decryptedBlob, originalFilename, 'Decrypted File');

        } catch (error) {
            console.error('Decryption error:', error);
            showError(`Decryption failed. Please check your password and file integrity. Details: ${error.message}`);
        }
    }

    // --- Cryptographic Functions (using Web Crypto API) ---
    async function getKeyFromPassword(password, salt) {
        const enc = new TextEncoder();
        const keyMaterial = await window.crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
        return window.crypto.subtle.deriveKey({ name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }
    
    async function encryptWithPassword(data, password, originalFilename) {
        const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
        const key = await getKeyFromPassword(password, salt);
        const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));
        const filenameBytes = new TextEncoder().encode(originalFilename);
        const filenameLengthBuffer = new ArrayBuffer(2);
        new DataView(filenameLengthBuffer).setUint16(0, filenameBytes.length, false);
        const encryptedContent = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, data);
        const encryptedBytes = new Uint8Array(encryptedContent);
        const result = new Uint8Array(SALT_SIZE + IV_SIZE + 2 + filenameBytes.length + encryptedBytes.length);
        let offset = 0;
        result.set(salt, offset); offset += salt.length;
        result.set(iv, offset); offset += iv.length;
        result.set(new Uint8Array(filenameLengthBuffer), offset); offset += 2;
        result.set(filenameBytes, offset); offset += filenameBytes.length;
        result.set(encryptedBytes, offset);
        return new Blob([result]);
    }

    async function decryptWithPassword(encryptedData, password) {
        const encryptedBytes = new Uint8Array(encryptedData);
        let offset = 0;
        const salt = encryptedBytes.slice(offset, offset + SALT_SIZE); offset += SALT_SIZE;
        const iv = encryptedBytes.slice(offset, offset + IV_SIZE); offset += IV_SIZE;
        const filenameLength = new DataView(encryptedBytes.buffer, offset, 2).getUint16(0, false); offset += 2;
        const filenameBytes = encryptedBytes.slice(offset, offset + filenameLength);
        const originalFilename = new TextDecoder().decode(filenameBytes); offset += filenameLength;
        const data = encryptedBytes.slice(offset);
        const key = await getKeyFromPassword(password, salt);
        const decryptedBuffer = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
        return { decryptedBuffer, originalFilename };
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
        link.textContent = `Download ${label} Again`;
        link.className = 'block w-full text-center mt-2 bg-gray-600 text-white font-semibold py-2 px-4 rounded-lg shadow-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500';
        let container = document.getElementById('download-links');
        if (!container) {
            container = document.createElement('div');
            container.id = 'download-links';
            container.className = 'mt-4 space-y-2';
            statusArea.appendChild(container);
        }
        container.innerHTML = '';
        container.appendChild(link);
        link.click();
    }
    function clearStatus() {
        statusArea.innerHTML = '';
    }

    // --- NEW: Dynamic Particle Background Logic ---
    const canvas = document.getElementById('particle-canvas');
    const ctx = canvas.getContext('2d');
    let particles = [];

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    class Particle {
        constructor(x, y, size, speedX, speedY) {
            this.x = x;
            this.y = y;
            this.size = size;
            this.speedX = speedX;
            this.speedY = speedY;
        }
        update() {
            if (this.x > canvas.width || this.x < 0) this.speedX = -this.speedX;
            if (this.y > canvas.height || this.y < 0) this.speedY = -this.speedY;
            this.x += this.speedX;
            this.y += this.speedY;
        }
        draw() {
            ctx.fillStyle = 'rgba(0, 255, 255, 0.5)';
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    function initParticles() {
        particles = [];
        const numberOfParticles = (canvas.width * canvas.height) / 9000;
        for (let i = 0; i < numberOfParticles; i++) {
            const size = Math.random() * 2 + 1;
            const x = Math.random() * canvas.width;
            const y = Math.random() * canvas.height;
            const speedX = (Math.random() * 0.5 - 0.25);
            const speedY = (Math.random() * 0.5 - 0.25);
            particles.push(new Particle(x, y, size, speedX, speedY));
        }
    }

    function connectParticles() {
        for (let a = 0; a < particles.length; a++) {
            for (let b = a; b < particles.length; b++) {
                const dx = particles[a].x - particles[b].x;
                const dy = particles[a].y - particles[b].y;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance < 120) {
                    ctx.strokeStyle = `rgba(0, 255, 255, ${1 - distance / 120})`;
                    ctx.lineWidth = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(particles[a].x, particles[a].y);
                    ctx.lineTo(particles[b].x, particles[b].y);
                    ctx.stroke();
                }
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (const particle of particles) {
            particle.update();
            particle.draw();
        }
        connectParticles();
        requestAnimationFrame(animate);
    }

    initParticles();
    animate();
});
