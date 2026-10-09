/**
 * security-engine.js — SecurePass AI Client-Side Deterministic Security Engine
 *
 * 100% Client-Side / Zero-Knowledge Password Security & Vulnerability Analysis.
 * Runs completely in the browser's JavaScript execution thread.
 * Plaintext passwords never leave the user's browser memory.
 */

window.SecurityEngine = (function () {
    'use strict';

    // ── Common Weak Root Wordlist ──────────────────────────────────────────
    const TOP_WEAK_ROOTS = new Set([
        'password', 'pass', 'admin', 'administrator', 'root', 'user', 'guest',
        'qwerty', 'asdf', 'zxcv', 'welcome', 'login', 'access', 'default',
        'letmein', 'monkey', 'dragon', 'football', 'baseball', 'soccer', 'hockey',
        'shadow', 'master', 'sunshine', 'princess', 'superman', 'batman',
        'trustno1', 'starwars', 'killer', 'secret', 'hunter', 'ranger',
        'system', 'security', 'secure', 'server', 'oracle', 'cisco', 'test',
        'testing', 'demo', 'sample', 'change', 'changeme', 'spring', 'summer',
        'autumn', 'winter', 'january', 'february', 'march', 'april', 'may',
        'june', 'july', 'august', 'september', 'october', 'november', 'december',
        'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
        'company', 'corporate', 'office', 'service', 'support', 'manager', 'director'
    ]);

    // ── Keyboard Adjacency Graph (QWERTY & Numpad) ─────────────────────────
    const KEYBOARD_ROWS = [
        '`1234567890-=',
        'qwertyuiop[]\\',
        'asdfghjkl;\'',
        'zxcvbnm,./'
    ];

    const NUMPAD_ROWS = [
        '789',
        '456',
        '123',
        '0'
    ];

    // Build subwalks of length 3+
    const KEYBOARD_WALK_SET = new Set();
    function registerWalks(rows) {
        for (const row of rows) {
            for (let len = 3; len <= 8; len++) {
                for (let i = 0; i <= row.length - len; i++) {
                    const sub = row.substring(i, i + len);
                    KEYBOARD_WALK_SET.add(sub);
                    KEYBOARD_WALK_SET.add(sub.split('').reverse().join(''));
                }
            }
        }
    }
    registerWalks(KEYBOARD_ROWS);
    registerWalks(NUMPAD_ROWS);

    // ── L33tspeak Substitution Map ─────────────────────────────────────────
    const LEET_REPLACEMENTS = {
        '@': 'a', '4': 'a',
        '8': 'b',
        '(': 'c', '<': 'c',
        '3': 'e',
        '9': 'g',
        '#': 'h',
        '!': 'i', '1': 'i', '|': 'i',
        '0': 'o',
        '$': 's', '5': 's',
        '7': 't', '+': 't',
        '2': 'z'
    };

    function normalizeLeetspeak(str) {
        let out = '';
        const lower = str.toLowerCase();
        for (let i = 0; i < lower.length; i++) {
            const ch = lower[i];
            out += LEET_REPLACEMENTS[ch] || ch;
        }
        return out;
    }

    // ── Single Password Pattern Detector ──────────────────────────────────
    function detectSinglePasswordPatterns(pw) {
        const patterns = [];
        const lower = pw.toLowerCase();
        const norm = normalizeLeetspeak(pw);

        // 1. Keyboard walk check
        for (const walk of KEYBOARD_WALK_SET) {
            if (lower.includes(walk)) {
                patterns.push({ type: 'keyboard_walk', match: walk, desc: `Keyboard pattern: "${walk}"` });
                break;
            }
        }

        // 2. Sequential numbers (e.g. 123, 789, 456)
        const seqNumMatch = lower.match(/(?:012|123|234|345|456|567|678|789|890|321|432|543|654|765|876|987)/);
        if (seqNumMatch) {
            patterns.push({ type: 'sequential_numbers', match: seqNumMatch[0], desc: `Sequential digits: "${seqNumMatch[0]}"` });
        }

        // 3. Repeated characters (e.g. aaa, 111, !!!)
        const repMatch = lower.match(/(.)\1{2,}/);
        if (repMatch) {
            patterns.push({ type: 'repeated_characters', match: repMatch[0], desc: `Repeated characters: "${repMatch[0]}"` });
        }

        // 4. Numeric suffix (e.g. pass123, secure2024!)
        const suffixMatch = pw.match(/\d{1,4}[!@#$%^&*()_+\-=]*$/);
        if (suffixMatch && suffixMatch[0].length >= 2) {
            patterns.push({ type: 'numeric_suffix', match: suffixMatch[0], desc: `Predictable trailing digits/symbols: "${suffixMatch[0]}"` });
        }

        // 5. Date / Year (1940-2099)
        const yearMatch = pw.match(/(?:19[4-9]\d|20[0-3]\d)/);
        if (yearMatch) {
            patterns.push({ type: 'year_pattern', match: yearMatch[0], desc: `Calendar year detected: "${yearMatch[0]}"` });
        }

        // 6. Dictionary root match (raw or normalized)
        let dictMatchFound = false;
        for (const root of TOP_WEAK_ROOTS) {
            if (lower.includes(root)) {
                patterns.push({ type: 'dictionary_word', match: root, desc: `Dictionary word: "${root}"` });
                dictMatchFound = true;
                break;
            } else if (norm.includes(root)) {
                patterns.push({ type: 'leetspeak_dictionary', match: root, desc: `L33tspeak dictionary root: "${root}"` });
                dictMatchFound = true;
                break;
            }
        }

        return patterns;
    }

    // ── Combinatorial Entropy & Crack Time Calculator ─────────────────────
    function calculateEntropy(pw) {
        if (!pw) return { entropy: 0, poolSize: 0, crackTime: '< 1 second', crackSeconds: 0 };

        const len = pw.length;
        let hasLower = false;
        let hasUpper = false;
        let hasDigit = false;
        let hasSpecial = false;

        for (let i = 0; i < len; i++) {
            const code = pw.charCodeAt(i);
            if (code >= 97 && code <= 122) hasLower = true;
            else if (code >= 65 && code <= 90) hasUpper = true;
            else if (code >= 48 && code <= 57) hasDigit = true;
            else hasSpecial = true;
        }

        let pool = 0;
        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSpecial) pool += 33;
        pool = Math.max(pool, 10);

        // Combinatorial raw entropy: L * log2(pool)
        let rawEntropy = len * (Math.log(pool) / Math.LN2);

        // Pattern-adjusted entropy deductions
        const patterns = detectSinglePasswordPatterns(pw);
        let deduction = 0;
        for (const p of patterns) {
            if (p.type === 'dictionary_word') deduction += 14;
            else if (p.type === 'leetspeak_dictionary') deduction += 10;
            else if (p.type === 'keyboard_walk') deduction += 12;
            else if (p.type === 'sequential_numbers') deduction += 8;
            else if (p.type === 'repeated_characters') deduction += 8;
            else if (p.type === 'year_pattern') deduction += 6;
            else if (p.type === 'numeric_suffix') deduction += 4;
        }

        const effectiveEntropy = Math.max(0, Math.round((rawEntropy - deduction) * 10) / 10);

        // Offline Fast GPU Attack Model: 100 Billion (1e11) guesses/second
        const guesses = Math.pow(pool, Math.min(len, 20)) / 2;
        const seconds = guesses / 100_000_000_000;

        let crackTime = 'Instant (< 1 sec)';
        if (seconds < 1) crackTime = 'Instant (< 1 sec)';
        else if (seconds < 60) crackTime = `${Math.round(seconds)} seconds`;
        else if (seconds < 3600) crackTime = `${Math.round(seconds / 60)} minutes`;
        else if (seconds < 86400) crackTime = `${Math.round(seconds / 3600)} hours`;
        else if (seconds < 86400 * 30) crackTime = `${Math.round(seconds / 86400)} days`;
        else if (seconds < 86400 * 365) crackTime = `${Math.round(seconds / (86400 * 30))} months`;
        else if (seconds < 86400 * 365 * 100) crackTime = `${Math.round(seconds / (86400 * 365))} years`;
        else if (seconds < 86400 * 365 * 10000) crackTime = 'Centuries (100+ years)';
        else crackTime = 'Millions of years (Unbreakable)';

        return {
            entropy: effectiveEntropy,
            rawEntropy: Math.round(rawEntropy * 10) / 10,
            poolSize: pool,
            crackTime: crackTime,
            crackSeconds: seconds,
            hasLower,
            hasUpper,
            hasDigit,
            hasSpecial
        };
    }

    // ── Single Password Assessment ─────────────────────────────────────────
    function assessPassword(password) {
        if (!password) {
            return {
                score: 0,
                risk_level: 'High Risk',
                length: 0,
                entropy: 0,
                crack_time: 'Instant',
                compliance_status: 'Non-Compliant',
                patterns: []
            };
        }

        const len = password.length;
        const ent = calculateEntropy(password);
        const patterns = detectSinglePasswordPatterns(password);

        let score = 0;

        // Length contribution (up to 40 pts)
        if (len >= 8) score += 15;
        if (len >= 12) score += 15;
        if (len >= 16) score += 10;

        // Character diversity contribution (up to 35 pts)
        if (ent.hasUpper) score += 10;
        if (ent.hasLower) score += 10;
        if (ent.hasDigit) score += 8;
        if (ent.hasSpecial) score += 7;

        // Entropy bonus (up to 25 pts)
        if (ent.entropy >= 60) score += 15;
        else if (ent.entropy >= 45) score += 10;
        else if (ent.entropy >= 30) score += 5;

        if (len >= 14 && ent.hasUpper && ent.hasLower && ent.hasDigit && ent.hasSpecial) {
            score += 10;
        }

        // Pattern deductions
        for (const p of patterns) {
            if (p.type === 'dictionary_word') score -= 25;
            else if (p.type === 'leetspeak_dictionary') score -= 18;
            else if (p.type === 'keyboard_walk') score -= 20;
            else if (p.type === 'sequential_numbers') score -= 12;
            else if (p.type === 'repeated_characters') score -= 15;
            else if (p.type === 'year_pattern') score -= 10;
            else if (p.type === 'numeric_suffix') score -= 8;
        }

        score = Math.max(5, Math.min(100, Math.round(score)));

        let riskLevel = 'High Risk';
        if (score >= 75) riskLevel = 'Low Risk';
        else if (score >= 50) riskLevel = 'Medium Risk';

        // Compliance checks
        const nistPass = len >= 8 && !patterns.some(p => p.type === 'dictionary_word' || p.type === 'keyboard_walk');
        const pciPass = len >= 12 && (ent.hasUpper || ent.hasLower) && (ent.hasDigit || ent.hasSpecial);
        const hipaaPass = len >= 10 && ent.hasUpper && ent.hasLower && ent.hasDigit;
        const isoPass = len >= 10 && !patterns.some(p => p.type === 'keyboard_walk' || p.type === 'repeated_characters');

        let complianceStatus = 'Non-Compliant';
        if (nistPass && pciPass && hipaaPass && isoPass) {
            complianceStatus = '100% Compliant (All Standards)';
        } else if (nistPass && pciPass) {
            complianceStatus = 'Partial Compliance (NIST + PCI)';
        } else if (nistPass) {
            complianceStatus = 'Baseline NIST Compliant';
        }

        // Recommendations
        const tips = [];
        if (len < 12) tips.push('Increase length to at least 12–16 characters');
        if (!ent.hasUpper) tips.push('Add uppercase characters (A–Z)');
        if (!ent.hasLower) tips.push('Add lowercase characters (a–z)');
        if (!ent.hasDigit) tips.push('Include numbers (0–9)');
        if (!ent.hasSpecial) tips.push('Add special symbols (!@#$%^&*)');
        if (patterns.some(p => p.type === 'keyboard_walk')) tips.push('Remove sequential keyboard walks (e.g. qwerty, 1234)');
        if (patterns.some(p => p.type === 'dictionary_word')) tips.push('Avoid common dictionary words and names');

        const recText = tips.length > 0
            ? `Recommended Actions: ${tips.slice(0, 3).join('. ')}.`
            : 'Password adheres to strong cryptographic standards. Store securely in a password manager.';

        return {
            risk_level: riskLevel,
            strength_score: score,
            length: len,
            has_uppercase: ent.hasUpper,
            has_lowercase: ent.hasLower,
            has_numbers: ent.hasDigit,
            has_special: ent.hasSpecial,
            entropy: ent.entropy,
            crack_time: ent.crackTime,
            compliance_status: complianceStatus,
            ai_recommendation: recText,
            patterns_detected: patterns.map(p => p.desc),
            nist_pass: nistPass,
            pci_pass: pciPass,
            hipaa_pass: hipaaPass,
            iso_pass: isoPass
        };
    }

    // ── Bulk Dataset In-Memory Aggregator ──────────────────────────────────
    function analyzeDataset(passwords) {
        if (!passwords || !passwords.length) {
            return null;
        }

        const total = passwords.length;
        const uniqueSet = new Set();
        const lengths = [];

        let lenLess8 = 0;
        let len8To11 = 0;
        let len12To15 = 0;
        let len16Plus = 0;

        let hasUpperCount = 0;
        let hasLowerCount = 0;
        let hasDigitCount = 0;
        let hasSpecialCount = 0;
        let bothCasesCount = 0;
        let allLowerCount = 0;

        let dictCount = 0;
        let walkCount = 0;
        let seqNumCount = 0;
        let numSuffixCount = 0;
        let repCharCount = 0;
        let yearCount = 0;
        let leetCount = 0;

        let weakCount = 0;
        let mediumCount = 0;
        let strongCount = 0;

        let scoreSum = 0;

        // Sample high-risk masked examples for report preview
        const highRiskSamples = [];

        for (let i = 0; i < total; i++) {
            const pw = passwords[i];
            if (!pw) continue;

            uniqueSet.add(pw);
            const len = pw.length;
            lengths.push(len);

            // Length distributions
            if (len < 8) lenLess8++;
            else if (len <= 11) len8To11++;
            else if (len <= 15) len12To15++;
            else len16Plus++;

            // Composition
            let hasU = false, hasL = false, hasD = false, hasS = false;
            for (let j = 0; j < len; j++) {
                const code = pw.charCodeAt(j);
                if (code >= 65 && code <= 90) hasU = true;
                else if (code >= 97 && code <= 122) hasL = true;
                else if (code >= 48 && code <= 57) hasD = true;
                else hasS = true;
            }

            if (hasU) hasUpperCount++;
            if (hasL) hasLowerCount++;
            if (hasD) hasDigitCount++;
            if (hasS) hasSpecialCount++;
            if (hasU && hasL) bothCasesCount++;
            if (hasL && !hasU && !hasD && !hasS) allLowerCount++;

            // Patterns
            const singlePatterns = detectSinglePasswordPatterns(pw);
            let hasDict = false, hasWalk = false, hasSeq = false, hasSuff = false, hasRep = false, hasLeet = false;

            for (const p of singlePatterns) {
                if (p.type === 'dictionary_word') hasDict = true;
                else if (p.type === 'leetspeak_dictionary') hasLeet = true;
                else if (p.type === 'keyboard_walk') hasWalk = true;
                else if (p.type === 'sequential_numbers') hasSeq = true;
                else if (p.type === 'numeric_suffix') hasSuff = true;
                else if (p.type === 'repeated_characters') hasRep = true;
                else if (p.type === 'year_pattern') yearCount++;
            }

            if (hasDict) dictCount++;
            if (hasLeet) leetCount++;
            if (hasWalk) walkCount++;
            if (hasSeq) seqNumCount++;
            if (hasSuff) numSuffixCount++;
            if (hasRep) repCharCount++;

            // Quick scoring
            const assessed = assessPassword(pw);
            scoreSum += assessed.strength_score;

            if (assessed.strength_score < 50 || len < 8) weakCount++;
            else if (assessed.strength_score < 75) mediumCount++;
            else strongCount++;

            // Collect safe masked previews for high-risk table
            if (assessed.strength_score < 45 && highRiskSamples.length < 8) {
                const mask = len <= 3
                    ? '••••'
                    : pw[0] + '•'.repeat(Math.min(len - 2, 6)) + pw[len - 1];
                highRiskSamples.push({
                    pattern: mask,
                    length: len,
                    entropy: assessed.entropy,
                    reason: singlePatterns.length ? singlePatterns[0].desc : 'Insufficient length or diversity',
                    risk_level: 'High'
                });
            }
        }

        // Statistical calculations
        lengths.sort((a, b) => a - b);
        const minLen = lengths.length ? lengths[0] : 0;
        const maxLen = lengths.length ? lengths[lengths.length - 1] : 0;
        const sumLen = lengths.reduce((acc, l) => acc + l, 0);
        const avgLen = total > 0 ? sumLen / total : 0;
        const mid = Math.floor(lengths.length / 2);
        const medianLen = lengths.length % 2 === 0
            ? (lengths[mid - 1] + lengths[mid]) / 2
            : (lengths[mid] || 0);

        let varianceSum = 0;
        for (const l of lengths) {
            varianceSum += Math.pow(l - avgLen, 2);
        }
        const stdDevLen = total > 0 ? Math.sqrt(varianceSum / total) : 0;

        const uniqueCount = uniqueSet.size;
        const dupCount = Math.max(0, total - uniqueCount);
        const avgScore = total > 0 ? scoreSum / total : 0;

        let overallRisk = 'High Risk';
        if (avgScore >= 75) overallRisk = 'Low Risk';
        else if (avgScore >= 50) overallRisk = 'Medium Risk';

        const pct = count => total > 0 ? Math.round((count / total) * 1000) / 10 : 0;

        // Attack simulations (percentages)
        const dictAttackPct = pct(dictCount + leetCount);
        const walkAttackPct = pct(walkCount);
        const patternAttackPct = pct(numSuffixCount + seqNumCount);
        const bruteEstimatePct = pct(lenLess8);

        const datasetStats = {
            total_passwords: total,
            unique_passwords: uniqueCount,
            duplicate_passwords: dupCount,
            average_length: Math.round(avgLen * 10) / 10,
            median_length: Math.round(medianLen * 10) / 10,
            std_dev_length: Math.round(stdDevLen * 10) / 10,
            min_length: minLen,
            max_length: maxLen,
            length_distribution: {
                less_than_8: lenLess8,
                between_8_and_11: len8To11,
                between_12_and_15: len12To15,
                greater_than_16: len16Plus
            },
            character_composition: {
                uppercase: { count: hasUpperCount, percentage: pct(hasUpperCount) },
                lowercase: { count: hasLowerCount, percentage: pct(hasLowerCount) },
                numbers: { count: hasDigitCount, percentage: pct(hasDigitCount) },
                special: { count: hasSpecialCount, percentage: pct(hasSpecialCount) },
                both_cases: { count: bothCasesCount, percentage: pct(bothCasesCount) },
                all_lowercase: { count: allLowerCount, percentage: pct(allLowerCount) }
            }
        };

        const patterns = {
            total_passwords: total,
            patterns: {
                dictionary_based: { count: dictCount, percentage: pct(dictCount) },
                keyboard_walk: { count: walkCount, percentage: pct(walkCount) },
                sequential_numbers: { count: seqNumCount, percentage: pct(seqNumCount) },
                numeric_suffix: { count: numSuffixCount, percentage: pct(numSuffixCount) },
                repeated_characters: { count: repCharCount, percentage: pct(repCharCount) },
                leetspeak: { count: leetCount, percentage: pct(leetCount) },
                name_based: { count: 0, percentage: 0 }
            },
            dictionary_count: dictCount,
            common_patterns: walkCount + seqNumCount + numSuffixCount,
            duplicate_count: dupCount,
            no_special: Math.max(0, total - hasSpecialCount),
            short_passwords: lenLess8,
            all_lowercase: allLowerCount
        };

        const attackScenarios = [
            {
                name: 'Dictionary Attack',
                key: 'dictionary_attack',
                probability: dictAttackPct,
                count: Math.round(dictAttackPct / 100 * total),
                total: total,
                description: 'Passwords matching dictionary wordlists or common terms'
            },
            {
                name: 'Keyboard Walk Attack',
                key: 'keyboard_walk_attack',
                probability: walkAttackPct,
                count: Math.round(walkAttackPct / 100 * total),
                total: total,
                description: 'Sequential keyboard patterns (qwerty, 123456, asdf)'
            },
            {
                name: 'Pattern Attack',
                key: 'pattern_attack',
                probability: patternAttackPct,
                count: Math.round(patternAttackPct / 100 * total),
                total: total,
                description: 'Predictable word + digit/symbol combinations'
            },
            {
                name: 'Brute Force Estimate',
                key: 'brute_force_estimate',
                probability: bruteEstimatePct,
                count: Math.round(bruteEstimatePct / 100 * total),
                total: total,
                description: 'Short passwords (<8 chars) vulnerable to rapid cracking'
            }
        ];

        return {
            dataset_stats: datasetStats,
            patterns: patterns,
            attack_scenarios: attackScenarios,
            distribution: {
                high: weakCount,
                medium: mediumCount,
                low: strongCount
            },
            score: Math.round(avgScore * 10) / 10,
            risk_level: overallRisk,
            password_examples: highRiskSamples
        };
    }

    return {
        assessPassword: assessPassword,
        analyzeDataset: analyzeDataset,
        calculateEntropy: calculateEntropy,
        detectPatterns: detectSinglePasswordPatterns
    };
})();
