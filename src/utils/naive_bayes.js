/**
 * Naive Bayes Email Classifier
 *
 * This classifier takes in email text (subject + body),
 * tokenizes it into words, and uses a Naive Bayes model
 * to estimate P(phishing | words).
 *
 * The model can be trained offline and embedded as JSON
 * (word counts + class counts), or incrementally trained
 * in the extension.
 */

class NaiveBayesEmailClassifier {
    constructor(model = null) {
        // Classes
        this.CLASSES = {
            PHISHING: 'phishing',
            LEGIT: 'legit'
        };

        // Laplace smoothing constant
        this.alpha = 1;

        // Model parameters
        this.wordCounts = {
            [this.CLASSES.PHISHING]: {}, // word -> count
            [this.CLASSES.LEGIT]: {}
        };
        this.classDocCounts = {
            [this.CLASSES.PHISHING]: 0,
            [this.CLASSES.LEGIT]: 0
        }; // number of training emails per class
        this.totalWordCounts = {
            [this.CLASSES.PHISHING]: 0,
            [this.CLASSES.LEGIT]: 0
        }; // total words per class
        this.vocab = new Set();

        if (model) {
            this.loadModel(model);
        }
    }

    /**
     * Load a precomputed model (for example from JSON).
     * Expected structure:
     * {
     *   wordCounts: { phishing: {word: count}, legit: {...} },
     *   classDocCounts: { phishing: N1, legit: N0 },
     *   totalWordCounts: { phishing: T1, legit: T0 }
     * }
     */
    loadModel(model) {
        this.wordCounts = model.wordCounts;
        this.classDocCounts = model.classDocCounts;
        this.totalWordCounts = model.totalWordCounts;
        this.vocab = new Set(
            Object.keys(this.wordCounts[this.CLASSES.PHISHING]).concat(
                Object.keys(this.wordCounts[this.CLASSES.LEGIT])
            )
        );
    }

    /**
     * Tokenize text: lowercase, remove non-letters, split on whitespace.
     */
    tokenize(text) {
        if (!text) return [];
        return text
            .toLowerCase()
            .replace(/[^a-z0-9\s]/g, ' ')
            .split(/\s+/)
            .filter(w => w.length > 1); // drop single-character junk
    }

    /**
     * Train on an array of labeled emails.
     * Each example: { text: "full email text", label: "phishing" | "legit" }
     */
    train(examples) {
        for (const ex of examples) {
            const label = ex.label === this.CLASSES.PHISHING
                ? this.CLASSES.PHISHING
                : this.CLASSES.LEGIT;

            this.classDocCounts[label] += 1;

            const tokens = this.tokenize(ex.text);
            for (const token of tokens) {
                this.vocab.add(token);
                if (!this.wordCounts[label][token]) {
                    this.wordCounts[label][token] = 0;
                }
                this.wordCounts[label][token] += 1;
                this.totalWordCounts[label] += 1;
            }
        }
    }

    /**
     * Compute log P(word | class) with Laplace smoothing.
     */
    _logPWordGivenClass(word, label) {
        const count = (this.wordCounts[label][word] || 0);
        const totalWords = this.totalWordCounts[label];
        const V = this.vocab.size || 1;
        const prob = (count + this.alpha) / (totalWords + this.alpha * V);
        return Math.log(prob);
    }

    /**
     * Compute log prior P(class).
     */
    _logPrior(label) {
        const totalDocs =
            this.classDocCounts[this.CLASSES.PHISHING] +
            this.classDocCounts[this.CLASSES.LEGIT];

        if (totalDocs === 0) {
            // If not trained, assume equal prior
            return Math.log(0.5);
        }
        const classDocs = this.classDocCounts[label];
        return Math.log(classDocs / totalDocs);
    }

    /**
     * Predict using email text (subject + body).
     * Returns:
     * {
     *   label: 'phishing' | 'legit',
     *   phishingProbability: number in [0, 1],
     *   legitProbability: number in [0, 1],
     *   logScores: { phishing: x, legit: y }
     * }
     */
    predict(text) {
        const tokens = this.tokenize(text);
        if (tokens.length === 0) {
            // If no content, default to legit with low confidence
            return {
                label: this.CLASSES.LEGIT,
                phishingProbability: 0.3,
                legitProbability: 0.7,
                logScores: {
                    [this.CLASSES.PHISHING]: Math.log(0.3),
                    [this.CLASSES.LEGIT]: Math.log(0.7)
                }
            };
        }

        // Start with log priors
        let logPhish = this._logPrior(this.CLASSES.PHISHING);
        let logLegit = this._logPrior(this.CLASSES.LEGIT);

        // Add log likelihoods
        for (const token of tokens) {
            // Only consider words we have seen in training
            if (!this.vocab.has(token)) continue;
            logPhish += this._logPWordGivenClass(token, this.CLASSES.PHISHING);
            logLegit += this._logPWordGivenClass(token, this.CLASSES.LEGIT);
        }

        // Convert log-scores to probabilities via softmax
        const maxLog = Math.max(logPhish, logLegit);
        const phishExp = Math.exp(logPhish - maxLog);
        const legitExp = Math.exp(logLegit - maxLog);
        const denom = phishExp + legitExp;
        const phishingProbability = phishExp / denom;
        const legitProbability = legitExp / denom;

        const label = phishingProbability >= legitProbability
            ? this.CLASSES.PHISHING
            : this.CLASSES.LEGIT;

        return {
            label,
            phishingProbability,
            legitProbability,
            logScores: {
                [this.CLASSES.PHISHING]: logPhish,
                [this.CLASSES.LEGIT]: logLegit
            }
        };
    }
}

// Existing global export:
window.NaiveBayesEmailClassifier =
    window.NaiveBayesEmailClassifier || new NaiveBayesEmailClassifier();

// Load pre-trained model.json (exported by the Python script)
(function loadModelFromJson() {
    try {
        const url = chrome.runtime.getURL("src/utils/model.json");
        fetch(url)
            .then(res => res.json())
            .then(model => {
                console.log("Naive Bayes model loaded:", model);
                window.NaiveBayesEmailClassifier.loadModel(model);
            })
            .catch(err => {
                console.error("Failed to load Naive Bayes model.json", err);
            });
    } catch (e) {
        console.error("Error initializing Naive Bayes model loader", e);
    }
})();
