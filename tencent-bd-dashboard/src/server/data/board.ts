import 'server-only';

import { and, asc, eq, sql } from 'drizzle-orm';

import { db } from '@/db/client';
import { motions, sopSteps, todos } from '@/db/schema';
import type { Motion, NewMotion, NewSopStep, NewTodo, SopStep, Todo } from '@/db/schema';
import type { TodoFilter } from '@/domain/schemas';
import type { TodoStatus } from '@/domain/enums';

// ---------------------------------------------------------------------------
// Next-Step Board (todos)
// ---------------------------------------------------------------------------

export function listTodos(filter: TodoFilter): Todo[] {
  const clauses = [];
  if (filter.owner) clauses.push(eq(todos.owner, filter.owner));
  if (filter.priority) clauses.push(eq(todos.priority, filter.priority));
  const where = clauses.length > 0 ? and(...clauses) : undefined;

  return db.select().from(todos).where(where).orderBy(asc(todos.status), asc(todos.position)).all();
}

export function getTodo(id: number): Todo | undefined {
  return db.select().from(todos).where(eq(todos.id, id)).get();
}

export function createTodo(values: NewTodo): Todo {
  return db.transaction(() => {
    const row = db
      .select({ maxPosition: sql<number>`coalesce(max(${todos.position}), -1)` })
      .from(todos)
      .where(eq(todos.status, values.status ?? 'Backlog'))
      .get();

    return db.insert(todos).values({ ...values, position: (row?.maxPosition ?? -1) + 1 }).returning().get();
  });
}

export function updateTodo(id: number, values: Partial<NewTodo>): Todo | undefined {
  return db
    .update(todos)
    .set({ ...values, updatedAt: new Date() })
    .where(eq(todos.id, id))
    .returning()
    .get();
}

export function deleteTodo(id: number): boolean {
  const result = db.delete(todos).where(eq(todos.id, id)).run();
  return result.changes > 0;
}

/** Move a card to a new column and position, renumbering the rest of both columns. */
export function moveTodo(id: number, status: TodoStatus, position: number): Todo | undefined {
  return db.transaction(() => {
    const card = getTodo(id);
    if (!card) return undefined;

    const targetColumn = db
      .select()
      .from(todos)
      .where(and(eq(todos.status, status), sql`${todos.id} != ${id}`))
      .orderBy(asc(todos.position))
      .all();

    const clampedPosition = Math.max(0, Math.min(position, targetColumn.length));
    targetColumn.splice(clampedPosition, 0, card);

    targetColumn.forEach((row, index) => {
      db.update(todos).set({ position: index }).where(eq(todos.id, row.id)).run();
    });

    return db
      .update(todos)
      .set({ status, position: clampedPosition, updatedAt: new Date() })
      .where(eq(todos.id, id))
      .returning()
      .get();
  });
}

// ---------------------------------------------------------------------------
// Development SOP checklist
// ---------------------------------------------------------------------------

export function listSopSteps(): SopStep[] {
  return db.select().from(sopSteps).orderBy(asc(sopSteps.position)).all();
}

/** Replace the whole checklist -- it is edited as a single ordered list. */
export function replaceSopSteps(bodies: string[]): SopStep[] {
  return db.transaction(() => {
    db.delete(sopSteps).run();
    bodies.forEach((body, position) => {
      db.insert(sopSteps).values({ body, position } satisfies NewSopStep).run();
    });
    return listSopSteps();
  });
}

// ---------------------------------------------------------------------------
// Sales motion playbooks
// ---------------------------------------------------------------------------

export function listMotions(query: string): Motion[] {
  if (!query) {
    return db.select().from(motions).orderBy(asc(motions.opportunity)).all();
  }

  const needle = `%${query.toLowerCase()}%`;
  return db
    .select()
    .from(motions)
    .where(
      sql`(lower(${motions.opportunity}) like ${needle}
        or lower(${motions.triggerSignals}) like ${needle}
        or lower(${motions.icp}) like ${needle}
        or lower(${motions.wedgeProduct}) like ${needle})`,
    )
    .orderBy(asc(motions.opportunity))
    .all();
}

export function getMotion(id: number): Motion | undefined {
  return db.select().from(motions).where(eq(motions.id, id)).get();
}

export function createMotion(values: NewMotion): Motion {
  return db.insert(motions).values(values).returning().get();
}

export function updateMotion(id: number, values: Partial<NewMotion>): Motion | undefined {
  return db
    .update(motions)
    .set({ ...values, updatedAt: new Date() })
    .where(eq(motions.id, id))
    .returning()
    .get();
}

export function deleteMotion(id: number): boolean {
  const result = db.delete(motions).where(eq(motions.id, id)).run();
  return result.changes > 0;
}
