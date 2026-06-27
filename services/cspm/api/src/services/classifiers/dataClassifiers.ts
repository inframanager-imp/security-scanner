/**
 * Data classifiers for DSPM sensitive-data discovery.
 *
 * Each classifier returns the number of matches in a text blob. We bundle them
 * by data type (PII / PHI / PCI / SECRETS / FINANCIAL).
 *
 * Implementation notes:
 *   - Credit card numbers are validated with Luhn before counting.
 *   - SSNs use a permissive 3-2-4 pattern (formatted or unformatted).
 *   - Credential patterns match well-known prefixes only (low false positive rate).
 *   - Pattern matching is line-by-line on a 1 MB sample to bound cost.
 */

export const CLASSIFIER_VERSION = '2026.06.18-v1';

export type DataType = 'PII' | 'PHI' | 'PCI' | 'SECRETS' | 'FINANCIAL' | 'IP';

interface ClassifierResult {
  type: DataType;
  matches: number;
  examples: string[]; // redacted exemplars (prefix + length) — never the value
  label: string;
}

const SSN_REGEX = /\b(?!000|666|9\d{2})\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}\b/g;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}\b/g;
const PHONE_REGEX = /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
const CARD_REGEX = /\b\d{13,19}\b/g;
const PRIVATE_KEY_REGEX = /-----BEGIN (?:RSA |EC |OPENSSH |PGP |ENCRYPTED |DSA )?PRIVATE KEY-----/g;
const AWS_KEY_REGEX = /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN_REGEX = /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g;
const SLACK_TOKEN_REGEX = /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g;
const OPENAI_KEY_REGEX = /\bsk-[A-Za-z0-9]{20,}\b/g;
const STRIPE_KEY_REGEX = /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g;
const IBAN_REGEX = /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g;
const SWIFT_REGEX = /\b[A-Z]{6}[A-Z2-9][A-NP-Z0-9]([A-Z0-9]{3})?\b/g;
const PHI_KEYWORDS = /\b(diagnosis|patient|prescription|icd-?10|medication|treatment|hipaa)\b/gi;

function luhnValid(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function countAndExamples(
  text: string,
  re: RegExp,
  extraValidator?: (m: string) => boolean,
  maxExamples = 3,
): { count: number; examples: string[] } {
  const examples: string[] = [];
  let count = 0;
  let m: RegExpExecArray | null;
  // Force global semantics
  const r = re.global ? re : new RegExp(re.source, re.flags + 'g');
  while ((m = r.exec(text)) !== null) {
    const val = m[0];
    if (extraValidator && !extraValidator(val)) continue;
    count++;
    if (examples.length < maxExamples) {
      // Redact: show first 3 chars + length only
      examples.push(`${val.slice(0, 3)}…(len=${val.length})`);
    }
    if (m.index === r.lastIndex) r.lastIndex++;
  }
  return { count, examples };
}

export function classifyText(text: string): ClassifierResult[] {
  const out: ClassifierResult[] = [];

  // Cap the inspected text to 1 MB
  const clipped = text.length > 1_048_576 ? text.slice(0, 1_048_576) : text;

  // PII
  const ssn = countAndExamples(clipped, SSN_REGEX);
  if (ssn.count > 0) out.push({ type: 'PII', matches: ssn.count, examples: ssn.examples, label: 'SSN' });
  const email = countAndExamples(clipped, EMAIL_REGEX);
  if (email.count > 0) out.push({ type: 'PII', matches: email.count, examples: email.examples, label: 'Email' });
  const phone = countAndExamples(clipped, PHONE_REGEX);
  if (phone.count > 0) out.push({ type: 'PII', matches: phone.count, examples: phone.examples, label: 'Phone' });

  // PCI (Luhn-validated)
  const card = countAndExamples(clipped, CARD_REGEX, luhnValid);
  if (card.count > 0) out.push({ type: 'PCI', matches: card.count, examples: card.examples, label: 'Credit card (Luhn)' });

  // SECRETS
  const pkey = countAndExamples(clipped, PRIVATE_KEY_REGEX);
  if (pkey.count > 0) out.push({ type: 'SECRETS', matches: pkey.count, examples: pkey.examples, label: 'Private key block' });
  const aws = countAndExamples(clipped, AWS_KEY_REGEX);
  if (aws.count > 0) out.push({ type: 'SECRETS', matches: aws.count, examples: aws.examples, label: 'AWS access key' });
  const gh = countAndExamples(clipped, GITHUB_TOKEN_REGEX);
  if (gh.count > 0) out.push({ type: 'SECRETS', matches: gh.count, examples: gh.examples, label: 'GitHub token' });
  const slack = countAndExamples(clipped, SLACK_TOKEN_REGEX);
  if (slack.count > 0) out.push({ type: 'SECRETS', matches: slack.count, examples: slack.examples, label: 'Slack token' });
  const oai = countAndExamples(clipped, OPENAI_KEY_REGEX);
  if (oai.count > 0) out.push({ type: 'SECRETS', matches: oai.count, examples: oai.examples, label: 'OpenAI key' });
  const stripe = countAndExamples(clipped, STRIPE_KEY_REGEX);
  if (stripe.count > 0) out.push({ type: 'SECRETS', matches: stripe.count, examples: stripe.examples, label: 'Stripe key' });

  // FINANCIAL
  const iban = countAndExamples(clipped, IBAN_REGEX);
  if (iban.count > 0) out.push({ type: 'FINANCIAL', matches: iban.count, examples: iban.examples, label: 'IBAN' });
  const swift = countAndExamples(clipped, SWIFT_REGEX);
  if (swift.count > 0) out.push({ type: 'FINANCIAL', matches: swift.count, examples: swift.examples, label: 'SWIFT/BIC' });

  // PHI (keyword heuristic)
  const phi = countAndExamples(clipped, PHI_KEYWORDS);
  if (phi.count > 3) out.push({ type: 'PHI', matches: phi.count, examples: phi.examples, label: 'PHI keywords' });

  return out;
}

export function aggregateByDataType(
  results: ClassifierResult[],
): { type: DataType; matches: number; labels: string[]; examples: string[] }[] {
  const map = new Map<DataType, { matches: number; labels: Set<string>; examples: string[] }>();
  for (const r of results) {
    if (!map.has(r.type)) map.set(r.type, { matches: 0, labels: new Set(), examples: [] });
    const slot = map.get(r.type)!;
    slot.matches += r.matches;
    slot.labels.add(r.label);
    slot.examples.push(...r.examples);
  }
  return Array.from(map.entries()).map(([type, v]) => ({
    type,
    matches: v.matches,
    labels: Array.from(v.labels),
    examples: v.examples.slice(0, 5),
  }));
}

export function confidenceFromMatches(matches: number, sampledObjects: number): 'HIGH' | 'MEDIUM' | 'LOW' {
  if (matches === 0 || sampledObjects === 0) return 'LOW';
  const rate = matches / sampledObjects;
  if (rate >= 1 || matches >= 10) return 'HIGH';
  if (rate >= 0.25 || matches >= 3) return 'MEDIUM';
  return 'LOW';
}

export function sensitivityForDataTypes(types: DataType[]): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
  if (types.includes('PCI') || types.includes('PHI') || types.includes('SECRETS')) return 'CRITICAL';
  if (types.includes('PII') || types.includes('FINANCIAL')) return 'HIGH';
  if (types.includes('IP')) return 'MEDIUM';
  return 'LOW';
}
