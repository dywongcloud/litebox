import productsJson from './seed-data/products.json';
import accountsJson from './seed-data/accounts.json';
import todosJson from './seed-data/todos.json';
import sopJson from './seed-data/sop.json';
import motionsJson from './seed-data/motions.json';

import { db, sqlite } from './client';
import {
  accountResearch,
  accounts,
  motions,
  productEvidence,
  products,
  sopSteps,
  todos,
} from './schema';
import type {
  AccountFit,
  AccountSize,
  AccountStage,
  CanSay,
  CommercialCategory,
  ConfidenceLevel,
  EvidenceConfidence,
  EvidenceLevel,
  KnowledgeLevel,
  Priority,
  ProductStatus,
  SellMode,
  TodoOwner,
  TodoPriority,
  TodoStatus,
} from '@/domain/enums';

/**
 * Loads the bundled initial corpus -- the same 181-product intelligence
 * library, SOP checklist, todo starters and sample account the source
 * application shipped as `seedProducts`/`seedAccounts`/etc -- into a freshly
 * migrated database.
 *
 * Ported data is cast through the domain enum types rather than validated with
 * Zod: this is a fixed, code-owned corpus checked into the repo, not user
 * input crossing a trust boundary. `productSchema` and friends still validate
 * every value a user or the Server Actions submit afterwards.
 */

interface SeedEvidence {
  level: string;
  statement: string;
  canSay: string;
  source: string;
  confidence: string;
  verified: string;
  notes: string;
}

interface SeedMessaging {
  technical: string;
  business: string;
  executive: string;
  safeClaim: string;
}

interface SeedPriorityScore {
  demand: number;
  rightToWin: number;
  entry: number;
  poc: number;
  expansion: number;
  revenue: number;
  rationale: string;
  validation: string;
}

interface SeedProduct {
  category: string;
  product: string;
  description: string;
  competitors: string;
  useCases: string;
  industries: string;
  companySize: string;
  customerGate: string;
  painPoints: string;
  strengths: string;
  weaknesses: string;
  productEntry: string;
  bdMotion: string;
  priority: string;
  knowledge: string;
  confidence: string;
  owner: string;
  status: string;
  notes: string;
  source: string;
  evidence: SeedEvidence[];
  messaging: SeedMessaging;
  discovery: string;
  buyingSignals: string;
  redFlags: string;
  proofRequired: string;
  objections: string;
  replacements: string;
  learningChecklist: string;
  priorityScore: SeedPriorityScore;
  commercialCategory: string;
  solutionStory: string;
  primaryCompetitor: string;
  referenceCustomers: string;
  tencentEdge: string;
  sellMode: string;
}

interface SeedAccount {
  company: string;
  region: string;
  industry: string;
  size: string;
  incumbent: string;
  products: string;
  pain: string;
  trigger: string;
  contact: string;
  path: string;
  stage: string;
  fit: string;
  next: string;
  due: string;
  notes: string;
}

interface SeedTodo {
  title: string;
  detail: string;
  owner: string;
  priority: string;
  status: string;
  due: string;
  link: string;
}

interface SeedMotion {
  id?: number;
  opportunity: string;
  triggerSignals: string;
  icp: string;
  discoveryQuestions: string;
  wedgeProduct: string;
  pocStrategy: string;
  successMetrics: string;
  expansionPath: string;
  risks: string;
  evidenceRequired: string;
}

const seedProducts = productsJson as SeedProduct[];
const seedAccounts = accountsJson as SeedAccount[];
const seedTodos = todosJson as SeedTodo[];
const seedSop = sopJson as string[];
const seedMotions = motionsJson as SeedMotion[];

/** Tables cleared and repopulated by a reseed. Never `users`, `sessions`, or `auditLog`. */
function clearBusinessTables(): void {
  db.delete(productEvidence).run();
  db.delete(products).run();
  db.delete(accountResearch).run();
  db.delete(accounts).run();
  db.delete(todos).run();
  db.delete(sopSteps).run();
  db.delete(motions).run();
}

/**
 * Wipe and reload the business tables from the bundled corpus.
 *
 * Runs inside a single transaction so a mid-load failure leaves the previous
 * data intact rather than a half-seeded database.
 */
export function applySeedCorpus(): { products: number; accounts: number; todos: number } {
  db.transaction(() => {
    clearBusinessTables();

    let position = 0;
    for (const step of seedSop) {
      db.insert(sopSteps).values({ body: step, position: position++ }).run();
    }

    for (const motion of seedMotions) {
      const { id: _seedId, ...values } = motion;
      db.insert(motions).values(values).run();
    }

    for (const todo of seedTodos) {
      db.insert(todos).values({
        title: todo.title,
        detail: todo.detail,
        owner: todo.owner as TodoOwner,
        priority: todo.priority as TodoPriority,
        status: todo.status as TodoStatus,
        dueOn: todo.due,
        link: todo.link,
      }).run();
    }

    for (const account of seedAccounts) {
      const inserted = db
        .insert(accounts)
        .values({
          company: account.company,
          region: account.region,
          industry: account.industry,
          size: account.size as AccountSize,
          incumbent: account.incumbent,
          products: account.products,
          pain: account.pain,
          trigger: account.trigger,
          contact: account.contact,
          path: account.path,
          stage: account.stage as AccountStage,
          fit: account.fit as AccountFit,
          nextAction: account.next,
          dueOn: account.due,
          notes: account.notes,
        })
        .returning({ id: accounts.id })
        .get();

      db.insert(accountResearch).values({ accountId: inserted.id }).run();
    }

    for (const product of seedProducts) {
      const inserted = db
        .insert(products)
        .values({
          category: product.category,
          product: product.product,
          description: product.description,
          competitors: product.competitors,
          useCases: product.useCases,
          industries: product.industries,
          companySize: product.companySize,
          customerGate: product.customerGate,
          painPoints: product.painPoints,
          strengths: product.strengths,
          weaknesses: product.weaknesses,
          productEntry: product.productEntry,
          bdMotion: product.bdMotion,
          notes: product.notes,
          source: product.source,
          priority: product.priority as Priority,
          knowledge: product.knowledge as KnowledgeLevel,
          confidence: product.confidence as ConfidenceLevel,
          status: product.status as ProductStatus,
          owner: product.owner,
          commercialCategory: product.commercialCategory as CommercialCategory,
          sellMode: product.sellMode as SellMode,
          solutionStory: product.solutionStory,
          primaryCompetitor: product.primaryCompetitor,
          referenceCustomers: product.referenceCustomers,
          tencentEdge: product.tencentEdge,
          messagingTechnical: product.messaging?.technical ?? '',
          messagingBusiness: product.messaging?.business ?? '',
          messagingExecutive: product.messaging?.executive ?? '',
          messagingSafeClaim: product.messaging?.safeClaim ?? '',
          discovery: product.discovery,
          buyingSignals: product.buyingSignals,
          redFlags: product.redFlags,
          proofRequired: product.proofRequired,
          objections: product.objections,
          replacements: product.replacements,
          learningChecklist: product.learningChecklist,
          scoreDemand: product.priorityScore?.demand ?? 3,
          scoreRightToWin: product.priorityScore?.rightToWin ?? 3,
          scoreEntry: product.priorityScore?.entry ?? 3,
          scorePoc: product.priorityScore?.poc ?? 3,
          scoreExpansion: product.priorityScore?.expansion ?? 3,
          scoreRevenue: product.priorityScore?.revenue ?? 3,
          scoreRationale: product.priorityScore?.rationale ?? '',
          scoreValidation: product.priorityScore?.validation ?? '',
        })
        .returning({ id: products.id })
        .get();

      let evidencePosition = 0;
      for (const evidence of product.evidence ?? []) {
        db.insert(productEvidence)
          .values({
            productId: inserted.id,
            level: evidence.level as EvidenceLevel,
            statement: evidence.statement,
            canSay: evidence.canSay as CanSay,
            source: evidence.source,
            confidence: evidence.confidence as EvidenceConfidence,
            verifiedOn: evidence.verified,
            notes: evidence.notes,
            position: evidencePosition++,
          })
          .run();
      }
    }
  });

  return {
    products: seedProducts.length,
    accounts: seedAccounts.length,
    todos: seedTodos.length,
  };
}

/** Row count guard so a caller can tell "already seeded" from "empty". */
export function isBusinessDataEmpty(): boolean {
  const row = sqlite.prepare('SELECT COUNT(*) AS n FROM products').get() as { n: number };
  return row.n === 0;
}
