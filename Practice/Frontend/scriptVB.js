// ==========================================
// Initialization & Elements
// ==========================================
const formVB = document.getElementById("upload_formVB");
const fileInputVB = document.getElementById("file_inputVB");
const dropZoneVB = document.getElementById("drop_zoneVB");
const dropTextVB = document.getElementById("drop_textVB");
const checkBtnVB = document.getElementById("check-btnVB");
const resetBtnVB = document.getElementById("reset-btnVB");
const statusVB = document.getElementById("statusVB");
const resultsContainer = document.getElementById("results_containerVB");

const themeToggleBtn = document.getElementById("theme-toggle-btn");
const helpBtn = document.getElementById("help-btn");
const helpModal = document.getElementById("help-modal");
const navbarHelpContainer = document.getElementById("navbar-help-container");
const instructionsWrapper = document.getElementById("instructions-wrapper");
const instructionsCard = document.getElementById("instructions-card");

let allFiles = [];

let lastAnalysisData = null;
let lastStatusState = 'idle';
let lastStatusErrorRaw = '';

const API_URL = "http://localhost:8000/upload/"; 

// ==========================================
// Localization Logic
// ==========================================
let currentLang = localStorage.getItem('lang') || 'en';

const translations = {
    en: {
        drop_text: "Drag & Drop files here or click to browse",
        drop_hint: "Supported: PE, PDF, Office, ZIP, Images, Scripts",
        drop_selected: "Selected Files:",
        analyze_btn: "Analyze Files",
        reset_btn: "Reset",
        footer_text: " 2026 Created By Valerii Baiko",
        
        settings_title: "Settings",
        lang_title: "Language",
        contrast_title: "High Contrast",
        contrast_desc: "Increase legibility & borders",
        size_title: "Interface Size",
        
        status_analyzing: "Performing deep static analysis...",
        status_success: "Analysis completed successfully!",
        status_error: "Error:",
        not_supported: "Not Supported",
        score_label: "Score",
        support_message: "Sorry, this file type is not supported for full analysis. Please check the list of supported extensions.",
        
        gen_info: "General Info",
        logical_type: "Logical Type:",
        dispatch_type: "Dispatch Type:",
        entropy: "Entropy:",
        double_ext: "Double Extension:",
        ext_mismatch: "Extension Mismatch:",
        
        score_breakdown: "Score Breakdown",
        def_checks: "Default Checks:",
        spec_checks: "Specific Checks:",
        raw_spec: "Raw Specific Points:",
        
        metadata_title: "Metadata",
        signals_title: "Detected Signals / Threats",
        
        table_cat: "Category",
        table_pattern: "Pattern / Indicator",
        table_sev: "Severity",
        
        val_detected: "Detected",
        val_none: "None",
        val_yes: "Yes",
        val_no: "No",
        val_high: "(High)",
        val_ok: "(OK)",

        inst_title: "How it works",
        inst_desc: "Welcome to StaticShield! This tool performs deep static analysis to detect potential threats in files ",
        inst_desc_bold: "without executing them.",
        inst_types: "Supported Types",
        inst_out: "Analysis Output",
        inst_out_desc: "You'll get a threat score (0-100), a detailed breakdown of detected signals, metadata extraction, and specific threat indicators.",
        inst_final: "Just drag & drop your files above to begin.",
        inst_note: "Note: The analysis is based on static signatures and heuristics. A 'Safe' score does not guarantee 100% safety.",

        list_exec: "Executables (PE: EXE, DLL, SYS, SCR)",
        list_docs: "Documents (PDF, Office(OLE, OOXML))",
        list_arch: "Archives (ZIP)",
        list_scripts: "Scripts (JS, PY, PS1, BAT, CMD, VBS)",
        list_imgs: "Images (PNG, JPG, GIF, BMP)"
    },
    uk: {
        drop_text: "Перетягніть файли сюди або натисніть для вибору",
        drop_hint: "Підтримується: PE, PDF, Office, ZIP, Images, Scripts",
        drop_selected: "Обрано файлів:",
        analyze_btn: "Аналізувати",
        reset_btn: "Скинути",
        footer_text: " 2026 Створено Валерієм Байко",
        
        settings_title: "Налаштування",
        lang_title: "Мова",
        contrast_title: "Високий контраст",
        contrast_desc: "Підвищити чіткість та межі",
        size_title: "Розмір інтерфейсу",
        
        status_analyzing: "Виконується глибокий статичний аналіз...",
        status_success: "Аналіз успішно завершено!",
        status_error: "Помилка:",
        not_supported: "Не підтримується",
        score_label: "Результат",
        support_message: "Вибачте, цей тип файлу не підтримується для повного аналізу. Будь ласка, перевірте список підтримуваних розширень.",
        
        gen_info: "Загальна Інформація",
        logical_type: "Логічний Тип:",
        dispatch_type: "Тип аналізу:",
        entropy: "Ентропія:",
        double_ext: "Подвійне розширення:",
        ext_mismatch: "Невідповідність розширення:",
        
        score_breakdown: "Деталізація Оцінки",
        def_checks: "Базові перевірки:",
        spec_checks: "Спеціалізовані перевірки:",
        raw_spec: "Необроблені спеціалізовані бали:",
        
        metadata_title: "Метадані",
        signals_title: "Виявлені Сигнали / Загрози",
        
        table_cat: "Категорія",
        table_pattern: "Патерн / Індикатор",
        table_sev: "Рівень",
        
        val_detected: "Виявлено",
        val_none: "Немає",
        val_yes: "Так",
        val_no: "Ні",
        val_high: "(Висока)",
        val_ok: "(Норма)",

        inst_title: "Як це працює",
        inst_desc: "Ласкаво просимо до StaticShield! Цей інструмент виконує глибокий статичний аналіз для виявлення потенційних загроз у файлах ",
        inst_desc_bold: "без їх виконання.",
        inst_types: "Підтримувані типи",
        inst_out: "Результат аналізу",
        inst_out_desc: "Ви отримаєте оцінку загрози (0-100), детальну розбивку виявлених сигналів, вилучені метадані та специфічні індикатори загроз.",
        inst_final: "Просто перетягніть файли вище, щоб розпочати.",
        inst_note: "Примітка: Аналіз базується на статичних сигнатурах та евристиці. Оцінка 'Безпечно' не гарантує 100% безпеки.",

        list_exec: "Виконувані файли (PE: EXE, DLL, SYS, SCR)",
        list_docs: "Документи (PDF, Office(OLE, OOXML))",
        list_arch: "Архіви (ZIP)",
        list_scripts: "Скрипти (JS, PY, PS1, BAT, CMD, VBS)",
        list_imgs: "Зображення (PNG, JPG, GIF, BMP)"
    },
    pl: {
        drop_text: "Przeciągnij pliki tutaj lub kliknij, aby wybrać",
        drop_hint: "Obsługiwane: PE, PDF, Office, ZIP, Images, Scripts",
        drop_selected: "Wybrane pliki:",
        analyze_btn: "Analizuj",
        reset_btn: "Resetuj",
        footer_text: " 2026 Stworzone przez Valerii Baiko",
        
        settings_title: "Konfiguracja",
        lang_title: "Język",
        contrast_title: "Wysoki Kontrast",
        contrast_desc: "Zwiększ czytelność i krawędzie",
        size_title: "Rozmiar Interfejsu",
        
        status_analyzing: "Wykonywanie głębokiej analizy statycznej...",
        status_success: "Analiza zakończona pomyślnie!",
        status_error: "Błąd:",
        not_supported: "Nieobsługiwane",
        score_label: "Wynik",
        support_message: "Przepraszamy, ten typ pliku nie jest obsługiwany w pełnej analizie. Sprawdź listę obsługiwanych rozszerzeń.",
        
        gen_info: "Informacje Ogólne",
        logical_type: "Typ Logiczny:",
        dispatch_type: "Typ analizy:",
        entropy: "Entropia:",
        double_ext: "Podwójne Rozszerzenie:",
        ext_mismatch: "Niezgodność Rozszerzenia:",
        
        score_breakdown: "Szczegóły Wyniku",
        def_checks: "Kontrole Podstawowe:",
        spec_checks: "Kontrole Specjalizowane:",
        raw_spec: "Surowe punkty specjalizowane:",

        metadata_title: "Metadane",
        signals_title: "Wykryte Sygnały / Zagrożenia",
        
        table_cat: "Kategoria",
        table_pattern: "Wzorzec / Wskaźnik",
        table_sev: "Poziom",
        
        val_detected: "Wykryto",
        val_none: "Brak",
        val_yes: "Tak",
        val_no: "Nie",
        val_high: "(Wysoka)",
        val_ok: "(OK)",

        inst_title: "Jak to działa",
        inst_desc: "Witamy w StaticShield! To narzędzie przeprowadza głęboką analizę statyczną w celu wykrycia potencjalnych zagrożeń w plikach ",
        inst_desc_bold: "bez ich uruchamiania.",
        inst_types: "Obsługiwane typy",
        inst_out: "Wynik analizy",
        inst_out_desc: "Otrzymasz ocenę zagrożenia (0-100), szczegółowe zestawienie wykrytych sygnałów, wyodrębnione metadane i specyficzne wskaźniki zagrożeń.",
        inst_final: "Po prostu przeciągnij pliki powyżej, aby rozpocząć.",
        inst_note: "Uwaga: Analiza opiera się na sygnaturach statycznych i heurystyce. Wynik 'Bezpieczny' nie gwarantuje 100% bezpieczeństwa.",

        list_exec: "Pliki wykonywalne (PE: EXE, DLL, SYS, SCR)",
        list_docs: "Dokumenty (PDF, Office(OLE, OOXML))",
        list_arch: "Archiwy (ZIP)",
        list_scripts: "Skrypty (JS, PY, PS1, BAT, CMD, VBS)",
        list_imgs: "Obrazy (PNG, JPG, GIF, BMP)"
    }
};

function t(key) {
    return translations[currentLang][key] || key;
}

function changeLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('lang', lang);
    
    document.querySelectorAll('.lang-btn').forEach(btn => {
        if (btn.dataset.lang === lang) {
            btn.dataset.active = "true";
        } else {
            delete btn.dataset.active;
        }
    });

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (translations[lang][key]) {
            el.innerText = translations[lang][key];
        }
    });

    if (allFiles.length > 0) updateFileDisplay();

    if (lastAnalysisData && lastAnalysisData.length > 0) {
        renderStatusVB();
        resultsContainer.innerHTML = ""; 
        renderResults(lastAnalysisData); 
    }
}

document.addEventListener('DOMContentLoaded', () => {
    changeLanguage(currentLang);
});

// ==========================================
// Theme & Modal Logic & Settings Dropdown Logic
// ==========================================

// Theme Switcher (Обробник кліку)
themeToggleBtn.addEventListener("click", () => {
    document.documentElement.classList.toggle("dark");

    const isDark = document.documentElement.classList.contains("dark");
    localStorage.setItem("theme", isDark ? "dark" : "light");
});

if (localStorage.getItem("theme") === "light") {
    document.documentElement.classList.remove("dark");
}

// Help Modal toggling
function toggleModal(open) {
    if (open) {
        helpModal.classList.add("open");
        document.body.style.overflow = "hidden";
    } else {
        helpModal.classList.remove("open");
        document.body.style.overflow = "";
    }
}

helpBtn.addEventListener("click", () => toggleModal(true));
document.querySelectorAll(".modal-close-trigger").forEach(el => {
    el.addEventListener("click", (e) => {
        if (e.target === el || el.tagName === 'BUTTON' || el.parentElement.tagName === 'BUTTON') {
             toggleModal(false);
        }
    });
});

// Settings Dropdown Logic
const settingsBtn = document.getElementById('settings-btn');
const settingsIcon = settingsBtn.querySelector('i');
const settingsDropdown = document.getElementById('settings-dropdown');
const settingsWrapper = document.getElementById('settings-wrapper');

let isSettingsOpen = false;

settingsBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    isSettingsOpen = !isSettingsOpen;
    toggleSettings(isSettingsOpen);
});

function toggleSettings(open) {
    if (open) {
        // Відкриваємо: Оберт за годинниковою + Розгортання меню
        settingsIcon.classList.add('rotate-180', 'text-accent');
        settingsDropdown.classList.remove('scale-y-0', 'opacity-0');
        settingsDropdown.classList.add('scale-y-100', 'opacity-100');
    } else {
        // Закриваємо: Оберт назад + Згортання меню
        settingsIcon.classList.remove('rotate-180', 'text-accent');
        settingsDropdown.classList.remove('scale-y-100', 'opacity-100');
        settingsDropdown.classList.add('scale-y-0', 'opacity-0');
    }
    isSettingsOpen = open;
}

document.addEventListener('click', (e) => {
    if (isSettingsOpen && !settingsWrapper.contains(e.target)) {
        toggleSettings(false);
    }
});

settingsDropdown.addEventListener('click', (e) => {
    e.stopPropagation();
});

// ==========================================
// Drag & Drop and File Handling
// ==========================================

["dragenter", "dragover", "dragleave", "drop"].forEach((evt) => {
  window.addEventListener(evt, (e) => {
    if (dropZoneVB && dropZoneVB.contains(e.target)) return;

    e.preventDefault();
  }, { capture: true });
});

function isLockedVB() {
  return fileInputVB.disabled;
}

dropZoneVB.addEventListener("dragover", (e) => {
  e.preventDefault();
  if (isLockedVB()) return;
  dropZoneVB.classList.add("border-accent", "bg-panel/80");
});

dropZoneVB.addEventListener("dragleave", () => {
  dropZoneVB.classList.remove("border-accent", "bg-panel/80");
});

dropZoneVB.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZoneVB.classList.remove("border-accent", "bg-panel/80");
  if (isLockedVB()) return;

  const files = Array.from(e.dataTransfer.files);
  handleFiles(files);
});

// Handle file selection via system dialog
fileInputVB.addEventListener("change", () => {
    const files = Array.from(fileInputVB.files);
    handleFiles(files);
    fileInputVB.value = null; 
});

function handleFiles(files) {
    for (let file of files) {
        const duplicate = allFiles.some(f => f.name === file.name && f.size === file.size);
        if (!duplicate) {
            allFiles.push(file);
        }
    }
    updateFileDisplay();
}

// Нова функція для перекладу статусу перевірки
function renderStatusVB() {
  if (lastStatusState === 'idle') {
    statusVB.innerHTML = '';
    return;
  }

  if (lastStatusState === 'analyzing') {
    statusVB.innerHTML =
      `<i class="fa-solid fa-circle-notch fa-spin text-accent mr-2"></i> ${t('status_analyzing')}`;
    return;
  }

  if (lastStatusState === 'success') {
    statusVB.innerHTML =
      `<span class="text-safe"><i class="fa-solid fa-check-circle mr-2"></i> ${t('status_success')}</span>`;
    return;
  }

  if (lastStatusState === 'error') {
    // Тут перекладається тільки "Error:", а текст помилки — як є (з Python)
    statusVB.innerHTML =
      `<span class="text-critical"><i class="fa-solid fa-triangle-exclamation mr-2"></i> ${t('status_error')} ${lastStatusErrorRaw}</span>`;
    return;
  }
}


// НОВА ФУНКЦІЯ: Видалення файлу зі списку за індексом
window.removeFile = function(index) {
    allFiles.splice(index, 1);
    updateFileDisplay();
    fileInputVB.value = null;
}

// Єдина функція для блокування/розблокування всього інтерфейсу
function toggleInterface(locked) {
    // 1. Форм-елементи (HTML attribute)
    fileInputVB.disabled = locked;
    checkBtnVB.disabled = locked;
    // Кнопку Reset блокуємо під час аналізу, але розблокуємо, якщо є результати (це обробимо окремо)
    if (locked) resetBtnVB.disabled = true;

    // 2. Drop Zone (CSS Class)
    // Клас .inactive тепер сам робить pointer-events: none
    if (locked) {
        dropZoneVB.classList.add("inactive");
        dropTextVB.classList.add("opacity-50");
    } else {
        dropZoneVB.classList.remove("inactive");
        dropTextVB.classList.remove("opacity-50");
    }
}

// Update the visual file list in the drop zone
function updateFileDisplay() {
    const count = allFiles.length;
    const wrapper = document.getElementById('drop_content_wrapper');
    const icon = wrapper.querySelector('i');
    const supportText = wrapper.querySelector('p');
    const isLocked = fileInputVB.disabled;

    const listPointerEvents = isLocked ? 'pointer-events-none' : 'pointer-events-auto';

    if (count > 0) {
        icon.classList.add('hidden');
        supportText.classList.add('hidden');

        let filesHtml = allFiles.map((f, index) => `
            <div class="flex items-center gap-3 bg-bg/80 px-4 py-2 rounded-lg mb-2 border border-border w-full max-w-md shadow-sm z-20 group/file">
                 <i class="fa-solid fa-file text-accent shrink-0"></i>
                 <span class="truncate text-sm text-gray-900 dark:text-gray-200 font-mono min-w-0 flex-1" title="${f.name}">${f.name}</span>
                 <div class="flex items-center gap-3 shrink-0 ml-auto">
                    <span class="text-xs text-gray-500 whitespace-nowrap">${(f.size / 1024).toFixed(1)} KB</span>
                    <button type="button" 
                        onclick="event.preventDefault(); event.stopPropagation(); window.removeFile(${index})" 
                        class="text-gray-400 hover:text-critical transition p-1.5 rounded-md hover:bg-critical/10 dark:hover:bg-critical/20 
                               opacity-0 group-hover/file:opacity-100 focus:opacity-100 transition-all duration-200
                               disabled:opacity-30" 
                        title="Remove file" ${isLocked ? 'disabled' : ''}>
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                 </div>
            </div>
        `).join('');
        dropTextVB.innerHTML = `
            <div class="flex flex-col items-center w-full z-20 relative">
                <div class="text-lg text-accent font-bold mb-4">${t('drop_selected')} ${count}</div>
                <div class="flex flex-col items-center w-full max-h-[300px] overflow-y-auto custom-scrollbar pr-2 ${listPointerEvents}" onclick="event.preventDefault(); event.stopPropagation();">
                    ${filesHtml}
                </div>
            </div>
        `;
        dropTextVB.classList.remove('text-center');
        dropTextVB.classList.add('w-full');

    } else {
        icon.classList.remove('hidden');
        supportText.classList.remove('hidden');
        dropTextVB.textContent = t('drop_text');
        dropTextVB.classList.add('text-center');
        dropTextVB.classList.remove('w-full');
    }
    // Update button states
    checkBtnVB.disabled = (allFiles.length === 0) || isLocked;

    const isAnalyzing = (typeof currentStatusState !== 'undefined' && currentStatusState === 'analyzing');
    resetBtnVB.disabled = allFiles.length === 0 || isAnalyzing;
}


// ==========================================
// Submit & Analysis Logic
// ==========================================

formVB.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (allFiles.length === 0) return;
    lastStatusState = 'analyzing';
    renderStatusVB();
    // 1. Lock Interface (Your specific logic)
    toggleInterface(true); // Блокуємо все
    updateFileDisplay();   // Оновлюємо (кнопки видалення стануть неактивними через isLockedVB) 
    
    // Анімація (без змін)
    if (instructionsCard && instructionsWrapper && navbarHelpContainer) {
        instructionsCard.classList.replace('scale-100', 'scale-0');
        instructionsCard.classList.replace('opacity-100', 'opacity-0');

        // 2. Через мить схлопуємо контейнер під нею
        setTimeout(() => {
            instructionsWrapper.classList.replace('max-h-[800px]', 'max-h-0');
            instructionsWrapper.classList.replace('mb-8', 'mb-0');
        }, 400);

        // 3. Анімуємо появу маленької іконки в навбарі (із затримкою)
        setTimeout(() => {
            navbarHelpContainer.classList.replace('scale-0', 'scale-100');
            navbarHelpContainer.classList.replace('opacity-0', 'opacity-100');
        }, 300);
    }

    resultsContainer.innerHTML = ""; 

    const formData = new FormData();
    for (let file of allFiles) {
        formData.append("file", file); 
    }

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ detail: response.statusText }));
            throw new Error(errorData.detail || `HTTP Error: ${response.status}`);
        }

        const data = await response.json();
        lastAnalysisData = data.results;
        lastStatusState = 'success';
        renderStatusVB();
        
        resetBtnVB.disabled = false;
        
        if (data.results && Array.isArray(data.results) && data.results.length > 0) {
            renderResults(data.results);
        } else {
            resultsContainer.innerHTML = '<div class="text-center text-gray-500 py-8 bg-panel rounded-xl border border-border">No analysis results received.</div>';
        }

    } catch (error) {
        lastStatusState = 'error';
        lastStatusErrorRaw = error.message || 'Unknown error';
        renderStatusVB();

        console.error("Upload error:", error);
        resetBtnVB.disabled = false;
    }
});

// Reset Logic
resetBtnVB.addEventListener("click", () => {
    formVB.reset();
    toggleInterface(false);

    if (instructionsCard && instructionsWrapper && navbarHelpContainer) {
        navbarHelpContainer.classList.replace('scale-100', 'scale-0');
        navbarHelpContainer.classList.replace('opacity-100', 'opacity-0');
        instructionsWrapper.classList.replace('max-h-0', 'max-h-[800px]');
        instructionsWrapper.classList.replace('mb-0', 'mb-8');
        setTimeout(() => {
            instructionsCard.classList.replace('scale-0', 'scale-100');
            instructionsCard.classList.replace('opacity-0', 'opacity-100');
        }, 200);
    }

    allFiles = [];
    lastAnalysisData = null;
    updateFileDisplay();
    lastStatusState = 'idle';
    lastStatusErrorRaw = '';
    renderStatusVB();
    resultsContainer.innerHTML = "";
    checkBtnVB.disabled = true;
    resetBtnVB.disabled = true;
});


// ============================================================
// Results Rendering Logic
// ============================================================

function getThreatMeta(level, supported) {
    const defaults = { 
        color: 'text-gray-400', 
        icon: 'fa-file', 
        hoverBorder: 'hover:border-gray-400', 
        hoverShadow: 'hover:shadow-gray-400/20',
        bgGradient: 'to-gray-400/5',      
        iconBg: 'bg-gray-400/20'
    };

    if (!supported) return { ...defaults, color: 'text-unknown', icon: 'fa-file-circle-question' };

    switch (level) {
        case 'safe': return { 
            color: 'text-safe', 
            icon: 'fa-shield', 
            hoverBorder: 'hover:border-safe', 
            hoverShadow: 'hover:shadow-safe/20',
            bgGradient: 'to-safe/5',       
            iconBg: 'bg-safe/20'
        };
        case 'medium': return { 
            color: 'text-medium', 
            icon: 'fa-shield-virus', 
            hoverBorder: 'hover:border-medium', 
            hoverShadow: 'hover:shadow-medium/20',
            bgGradient: 'to-medium/5',
            iconBg: 'bg-medium/20'
        };
        case 'high': return { 
            color: 'text-high', 
            icon: 'fa-triangle-exclamation', 
            hoverBorder: 'hover:border-high', 
            hoverShadow: 'hover:shadow-high/20',
            bgGradient: 'to-high/5',
            iconBg: 'bg-high/20'
        };
        case 'critical': return { 
            color: 'text-critical', 
            icon: 'fa-radiation', 
            hoverBorder: 'hover:border-critical', 
            hoverShadow: 'hover:shadow-critical/20',
            bgGradient: 'to-critical/5',
            iconBg: 'bg-critical/20'
        };
        default: return defaults;
    }
}


function renderResults(resultsArray) {
    resultsArray.forEach((fileData, index) => {
        const supported = fileData.supported !== false;
        const threatLevel = fileData.threat_level || 'unknown';
        const meta = getThreatMeta(threatLevel, supported);
        const score = supported ? fileData.score : 0;
        
        const card = document.createElement('div');
        card.className = `group bg-panel border border-border rounded-xl overflow-hidden transition-all duration-300 ${meta.hoverBorder} hover:shadow-lg ${meta.hoverShadow} z-10 relative`;
        card.style.animationDelay = `${index * 0.1}s`;

        let cardHeaderHtml = `
            <div class="p-4 sm:p-6 flex flex-col md:flex-row gap-4 items-start md:items-center justify-between cursor-pointer bg-gradient-to-r from-transparent via-transparent ${meta.bgGradient} dark:${meta.bgGradient.replace('/5', '/10')}" onclick="toggleDetails('details-${index}', 'arrow-${index}')">
                <div class="flex items-center gap-4 flex-1 min-w-0">
                    <div class="text-4xl ${meta.color} p-3 ${meta.iconBg} dark:${meta.iconBg.replace('/20', '/10')} rounded-xl">
                        <i class="fa-solid ${meta.icon}"></i>
                    </div>
                    <div class="min-w-0 flex-1">
                        <h3 class="font-bold text-lg text-gray-900 dark:text-gray-100 truncate" title="${fileData.filename}">${fileData.filename}</h3>
                        <div class="flex flex-wrap gap-2 text-xs text-gray-600 dark:text-gray-400 mt-2">
                            <span class="px-2 py-1 rounded-md border border-gray-300 dark:border-border bg-gray-100 dark:bg-bg uppercase">${fileData.extension}</span>
                            <span class="px-2 py-1 rounded-md border border-gray-300 dark:border-border bg-gray-100 dark:bg-bg">${(fileData.size / 1024).toFixed(1)} KB</span>
                            <span class="px-2 py-1 rounded-md border border-gray-300 dark:border-border bg-gray-100 dark:bg-bg">Magic: ${fileData.magicType}</span>
                        </div>
                    </div>
                </div>

                <div class="flex items-center gap-6 w-full md:w-auto justify-between md:justify-end mt-4 md:mt-0">
        `;

        if (supported) {
            // Badges
            if (fileData.top_threats && fileData.top_threats.length > 0) {
                cardHeaderHtml += `<div class="hidden lg:flex gap-2">`;
                fileData.top_threats.slice(0, 3).forEach(threat => {
                     let badgeColor = 'gray';
                    if (threat.severity >= 9) badgeColor = 'critical';
                    else if (threat.severity >= 7) badgeColor = 'high';
                    else if (threat.severity >= 5) badgeColor = 'medium';
                     cardHeaderHtml += `<span class="px-2 py-1 bg-${badgeColor}/10 text-${badgeColor} text-xs font-medium rounded border border-${badgeColor}/20 truncate max-w-[140px]" title="${threat.category}: ${threat.pattern}">${threat.category}</span>`;
                });
                cardHeaderHtml += `</div>`;
            }

            // Radial Gauge (Target Style)
            cardHeaderHtml += `
                <div class="flex items-center gap-3 ml-auto md:ml-0">
                    <div class="text-right">
                        <div class="text-xs text-gray-400 uppercase font-semibold">${t('score_label')}</div>
                        <div class="font-bold text-xl ${meta.color}">${score}/100</div>
                    </div>
                    <div class="radial-progress ${threatLevel}">
                        <div class="gauge-text">
                            <span class="text-xs font-bold ${meta.color}">${threatLevel.toUpperCase()}</span>
                        </div>
                    </div>
                </div>
            `
        } else {
             cardHeaderHtml += `
                <div class="text-right px-4 py-2 rounded-lg border transition-colors ml-auto md:ml-0 bg-gray-100 border-gray-200 dark:bg-gray-800/50 dark:border-gray-700/50">
                    <span class="text-sm font-medium text-gray-600 dark:text-gray-400"><i class="fa-solid fa-ban mr-2"></i>${t('not_supported')}</span>
                </div>
            `;
        }

        cardHeaderHtml += `
                    <div class="w-8 h-8 flex items-center justify-center rounded-full hover:bg-white/10 transition-colors">
                        <i id="arrow-${index}" class="fa-solid fa-chevron-down text-gray-500 transition-transform duration-300 group-hover:text-gray-300"></i>
                    </div>
                </div>
            </div>
        `;

        let cardBodyHtml = `
            <div id="details-${index}" class="hidden border-t border-border bg-bg/30 backdrop-blur-sm transition-all relative z-0">
                <div class="p-6 space-y-8">
        `;

        if (supported) {
            const details = fileData.details || {};
            const specific = details.specific_check || {};

            cardBodyHtml += `
                <div class="grid grid-cols-1 lg:grid-cols-12 gap-8">
                    <div class="lg:col-span-5 space-y-6">
                        <div>
                             <h4 class="text-accent text-sm uppercase font-bold mb-3 flex items-center gap-2">
                                <i class="fa-solid fa-circle-info"></i> ${t('gen_info')}
                             </h4>
                             <ul class="text-sm text-gray-700 dark:text-gray-300 space-y-1 bg-white dark:bg-panel p-4 rounded-xl border border-gray-200 dark:border-border shadow-sm">
                                <li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5"><span>${t('logical_type')}</span> <span class="text-gray-900 dark:text-white font-medium uppercase">${fileData.logicalType}</span></li>
                                <li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5"><span>${t('dispatch_type')}</span> <span class="text-gray-900 dark:text-white font-medium uppercase">${details.dispatch_type}</span></li>
                                ${renderEntropy(details.default_checks?.entropy)}
                                ${renderGeneralChecks(details.default_checks, fileData.logicalType)} 
                             </ul>
                        </div>
                        ${renderScoreBreakdown(fileData.score_breakdown)}
                    </div>

                    <div class="lg:col-span-7">
                        <h4 class="text-accent text-sm uppercase font-bold mb-3 flex items-center gap-2">
                            <i class="fa-solid fa-file-code"></i> ${specific.type ? specific.type.toUpperCase() : 'FILE'} ${t('metadata_title')}
                        </h4>
                        <div class="text-sm text-gray-700 dark:text-gray-300 bg-white dark:bg-panel p-4 rounded-xl border border-gray-200 dark:border-border shadow-sm max-h-[280px] overflow-y-auto custom-scrollbar space-y-2">
                            ${renderMetadata(specific.meta)}
                        </div>
                    </div>
                </div>
            `;

            cardBodyHtml += `
                <div class="pt-4 border-t border-gray-200 dark:border-border/50">
                     <h4 class="text-${meta.color.split('-')[1]} text-sm uppercase font-bold mb-4 flex items-center gap-2">
                        <i class="fa-solid fa-bug"></i> ${t('signals_title')}
                     </h4>
                     <div class="overflow-hidden rounded-xl border border-gray-200 dark:border-border bg-white dark:bg-panel shadow-sm">
                        <div class="overflow-x-auto custom-scrollbar">
                            <table class="min-w-full text-left text-sm">
                                <thead class="bg-gray-50 dark:bg-black/30 text-xs uppercase text-gray-500 dark:text-gray-400 font-semibold">
                                    <tr>
                                        <th class="p-4 whitespace-nowrap">${t('table_cat')}</th>
                                        <th class="p-4">${t('table_pattern')}</th>
                                        <th class="p-4 text-right whitespace-nowrap">${t('table_sev')} (1-10)</th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-gray-100 dark:divide-border/50">
                                    ${renderSignalsTable(specific.signals)}
                                </tbody>
                            </table>
                        </div>
                     </div>
                </div>
            `;

        } else {
            cardBodyHtml += `
                <div class="text-center py-12 text-gray-400 flex flex-col items-center">
                    <i class="fa-solid fa-triangle-exclamation text-5xl text-unknown mb-6 opacity-50"></i>
                    <p class="text-lg font-medium text-gray-300">${t('support_message')}</p>
                </div>
            `;
        }

        cardBodyHtml += `</div></div>`; 
        card.innerHTML = cardHeaderHtml + cardBodyHtml;
        resultsContainer.appendChild(card);
    });
}


// --- Helper Functions for Rendering ---

// Toggle Accordion (Must be global)
window.toggleDetails = function(detailsId, arrowId) {
    const detailsEl = document.getElementById(detailsId);
    const arrowEl = document.getElementById(arrowId);
    if (detailsEl && arrowEl) {
        detailsEl.classList.toggle('hidden');
        arrowEl.classList.toggle('rotate-180');
    }
}

// Render Entropy
function renderEntropy(entropy) {
    if (!entropy) return '';
    const color = entropy.too_high ? 'text-high' : 'text-safe';
    return `<li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5">
                <span>${t('entropy')}</span> 
                <span class="${color} font-medium">${entropy.value.toFixed(2)} <span class="text-xs ml-1">${entropy.too_high ? t('val_high') : t('val_ok')}</span></span>
            </li>`;
}

// Render General Checks
function renderGeneralChecks(checks, logicalType) {
    if (!checks) return '';
    let html = '';

    if (checks.double_extension) {
        const isDouble = checks.double_extension.found;
        const color = isDouble ? 'text-high' : 'text-safe';
        html += `<li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5">
            <span>${t('double_ext')}</span> <span class="${color} font-bold break-all">${isDouble ? t('val_detected') : t('val_none')}</span>
        </li>`;
    }

    if (logicalType !== 'text' && logicalType !== 'script') {
        if (checks.extension_mismatch) {
             const isMismatch = checks.extension_mismatch.found;
             const color = isMismatch ? 'text-high' : 'text-safe';
             html += `<li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5">
                 <span>${t('ext_mismatch')}</span> <span class="${color} font-medium">${isMismatch ? t('val_detected') : t('val_none')}</span>
             </li>`;
        }
    }
    return html;
}

// Render Score Breakdown
function renderScoreBreakdown(breakdown) {
    if (!breakdown) return '';
    return `
        <div>
            <h4 class="text-accent text-sm uppercase font-bold mb-3 flex items-center gap-2"><i class="fa-solid fa-chart-pie"></i> ${t('score_breakdown')}</h4>
            <ul class="text-sm text-gray-700 dark:text-gray-300 space-y-1 bg-white dark:bg-panel p-4 rounded-xl border border-gray-200 dark:border-border shadow-sm">
                <li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5"><span>${t('def_checks')}</span> <span class="font-medium text-gray-900 dark:text-white">${breakdown.default} pts</span></li>
                <li class="flex justify-between py-1 border-b border-gray-100 dark:border-white/5"><span>${t('spec_checks')}</span> <span class="font-medium text-gray-900 dark:text-white">${breakdown.specific} pts</span></li>
                <li class="flex justify-between text-gray-500 dark:text-gray-500 text-xs pt-2 mt-1"><span>${t('raw_spec')}</span> <span>${breakdown.raw_specific} pts</span></li>
            </ul>
        </div>
    `;
}

// Render Metadata
function renderMetadata(meta) {
    if (!meta || Object.keys(meta).length === 0) return '<div class="text-center text-gray-500 italic py-4">No specific metadata found.</div>';
    
    return Object.entries(meta).map(([key, value]) => {
        let displayValue = value;

        if (typeof value === 'boolean') {
            displayValue = value ? `<span class="text-safe">${t('val_yes')}</span>` : `<span class="text-gray-500">${t('val_no')}</span>`;
        }

        if (key === 'overlay_size' && typeof value === 'number') {
            const mbValue = (value / (1024*1024)).toFixed(2); 
            displayValue = `
                <span>${mbValue} MB</span>
                <span class="text-xs text-gray-400 ml-1">(${value.toLocaleString()} bytes)</span>
            `;
        }

        return `
        <div class="flex flex-col sm:flex-row justify-between gap-1 sm:gap-4 hover:bg-gray-50 dark:hover:bg-white/5 p-2 rounded transition-colors break-words">
            <span class="text-gray-600 dark:text-gray-400 font-mono text-xs uppercase tracking-wider shrink-0">${key.replace(/_/g, ' ')}:</span>
            <span class="text-gray-900 dark:text-white text-left sm:text-right font-medium">${displayValue}</span>
        </div>
    `}).join('');
}

// Render Signals Table
function renderSignalsTable(signals) {
    if (!signals || signals.length === 0) {
        return '<tr><td colspan="3" class="p-8 text-center text-gray-500 italic">No specific threats or signals detected for this file.</td></tr>';
    }
    return signals.map(sig => {
        let sevColor = 'text-safe';
        let sevBg = 'bg-safe/10';
        if (sig.severity >= 9) { sevColor = 'text-critical'; sevBg = 'bg-critical/10'; }
        else if (sig.severity >= 7) { sevColor = 'text-high'; sevBg = 'bg-high/10'; }
        else if (sig.severity >= 5) { sevColor = 'text-medium'; sevBg = 'bg-medium/10'; }

        return `
            <tr class="hover:bg-gray-50 dark:hover:bg-white/5 transition-colors">
                <td class="p-4 font-medium text-gray-900 dark:text-gray-200">${sig.category}</td>
                <td class="p-4 font-mono text-xs text-gray-600 dark:text-gray-400 break-all leading-relaxed">${sig.pattern}</td>
                <td class="p-4 text-right">
                    <span class="inline-block font-bold ${sevColor} ${sevBg} px-3 py-1 rounded-lg">${sig.severity}</span>
                </td>
            </tr>
        `;
    }).join('');
}

// ==========================================
// Accessibility: High Contrast Logic
// ==========================================
const contrastToggle = document.getElementById('contrast-toggle');

// 1. Check saved preference on load
if (localStorage.getItem('high-contrast') === 'true') {
    document.documentElement.classList.add('contrast');
    if (contrastToggle) contrastToggle.checked = true;
}

// 2. Handle toggle change
if (contrastToggle) {
    contrastToggle.addEventListener('change', (e) => {
        const isEnabled = e.target.checked;
        
        if (isEnabled) {
            document.documentElement.classList.add('contrast');
        } else {
            document.documentElement.classList.remove('contrast');
        }
        
        localStorage.setItem('high-contrast', isEnabled);
    });
}

// ==========================================
// Accessibility: UI Scaling (Text Size)
// ==========================================
const sizeSlider = document.getElementById('size-slider');
const sizeLabel = document.getElementById('size-label');

const sizeMap = {
    1: { value: '100%', label: '100%' },
    2: { value: '110%', label: '110%' },
    3: { value: '125%', label: '125%' }
};

function applySize(step) {
    const setting = sizeMap[step];
    if (!setting) return;

    document.documentElement.style.fontSize = setting.value;
    
    if (sizeLabel) sizeLabel.textContent = setting.label;
    
    localStorage.setItem('ui-scale', step);
}

// 1. Check saved preference on load
const savedStep = localStorage.getItem('ui-scale') || 1;
if (sizeSlider) {
    sizeSlider.value = savedStep;
    applySize(savedStep);
}

// 2. Handle slider change
if (sizeSlider) {
    sizeSlider.addEventListener('input', (e) => {
        applySize(e.target.value);
    });
}