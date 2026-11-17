import hashlib
import json

from .audit import write
from .grants import Grants
from .policy import Policies


class StalePreviewError(ValueError):
    """影响预览所依据的数据已变化，过期预览不能作为发布结果。"""

    def __init__(self, changes):
        self.changes = changes
        super().__init__("影响预览已过期：" + "；".join(change["message"] for change in changes))


def _fingerprint(basis):
    canonical = json.dumps(basis, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _evaluate(basis, product, recipient, purpose, draft):
    """沿来源血缘逐项核对：记录可用、来源在用、许可有效、规则允许。"""
    eligible = True
    details = []
    for asset_id in product["inputs"]:
        asset = basis["assets"][asset_id]
        source = basis["sources"][asset["source"]]
        grant = basis["permits"].get(asset["source"], {}).get(recipient)
        policy = basis["policies"].get(source["jurisdiction"], {}).get(source["classification"], {}).get(purpose)
        published = policy[0] if policy else "deny"
        matches = draft is not None and (source["jurisdiction"], source["classification"], purpose) == draft[0]
        decision = draft[1] if matches else published
        usable = asset["state"] == "active" and bool(source["active"])
        eligible = eligible and usable and bool(grant) and decision == "allow"
        details.append({
            "asset": asset_id, "source": asset["source"], "owner": source["owner"],
            "jurisdiction": source["jurisdiction"], "classification": source["classification"],
            "grant": grant, "matches": matches,
            "decision_before": published, "decision_after": decision,
        })
    return eligible, details


def _format_policy(value):
    return "无" if value is None else "{}（第{}版）".format(value[0], value[1])


class Staging:
    """规则修订的待发布登记、影响预览与发布核对。

    修订先进入 pending 状态，不影响在途交付；预览把计算所依据的来源、
    许可与规则事实存入快照并取指纹；发布时重新采集同一批事实核对指纹，
    若期间发生来源停用、许可撤销等变化则拒绝按过期预览发布。
    """

    def __init__(self, connection):
        self.connection = connection
        self.grants = Grants(connection)
        self.policies = Policies(connection)

    def propose(self, revision_id, jurisdiction, classification, purpose, decision, at, actor):
        if decision not in {"allow", "deny"}:
            raise ValueError("规则决策无效")
        pending = self.connection.execute(
            "SELECT id FROM rule_revisions WHERE jurisdiction=? AND classification=? AND purpose=? AND state='pending'",
            (jurisdiction, classification, purpose),
        ).fetchall()
        with self.connection:
            for old in pending:
                self.connection.execute("UPDATE rule_revisions SET state='superseded' WHERE id=?", (old["id"],))
                write(self.connection, at, actor, "staging.supersede", old["id"], {"replaced_by": revision_id})
            self.connection.execute(
                "INSERT INTO rule_revisions(id,jurisdiction,classification,purpose,decision,state,created_at,created_by) "
                "VALUES(?,?,?,?,?,'pending',?,?)",
                (revision_id, jurisdiction, classification, purpose, decision, at, actor),
            )
            write(self.connection, at, actor, "staging.propose", revision_id, {
                "jurisdiction": jurisdiction, "classification": classification, "purpose": purpose,
                "decision": decision, "supersedes": [old["id"] for old in pending],
            })

    def get(self, revision_id):
        revision = self._revision(revision_id)
        previews = self.connection.execute(
            "SELECT id,created_at,fingerprint,impacts FROM rule_previews WHERE revision_id=? ORDER BY rowid",
            (revision_id,),
        ).fetchall()
        return {
            **revision,
            "previews": [
                {"id": row["id"], "created_at": row["created_at"], "fingerprint": row["fingerprint"],
                 "impacts": json.loads(row["impacts"])}
                for row in previews
            ],
        }

    def preview(self, revision_id, preview_id, at, actor):
        revision = self._revision(revision_id)
        if revision["state"] != "pending":
            raise ValueError("规则修订不在待发布状态")
        basis = self._basis(revision, at)
        impacts = self._impacts(revision, basis)
        fingerprint = _fingerprint(basis)
        snapshot = json.dumps({"at": at, "basis": basis}, ensure_ascii=False, sort_keys=True)
        with self.connection:
            self.connection.execute(
                "INSERT INTO rule_previews(id,revision_id,created_at,fingerprint,snapshot,impacts) VALUES(?,?,?,?,?,?)",
                (preview_id, revision_id, at, fingerprint, snapshot,
                 json.dumps(impacts, ensure_ascii=False, sort_keys=True)),
            )
            write(self.connection, at, actor, "staging.preview", preview_id,
                  {"revision": revision_id, "impacts": len(impacts)})
        return {"id": preview_id, "revision": revision_id, "created_at": at,
                "fingerprint": fingerprint, "impacts": impacts}

    def changes(self, preview_id, at):
        row = self.connection.execute("SELECT * FROM rule_previews WHERE id=?", (preview_id,)).fetchone()
        if row is None:
            raise KeyError(preview_id)
        revision = self._revision(row["revision_id"])
        basis = self._basis(revision, at)
        old = json.loads(row["snapshot"])["basis"]
        changes = self._diff(old, basis, at)
        return {"preview": preview_id, "revision": row["revision_id"], "fresh": not changes, "changes": changes}

    def publish(self, revision_id, at, actor):
        revision = self._revision(revision_id)
        if revision["state"] != "pending":
            raise ValueError("规则修订不在待发布状态")
        preview = self.connection.execute(
            "SELECT * FROM rule_previews WHERE revision_id=? ORDER BY rowid DESC LIMIT 1", (revision_id,),
        ).fetchone()
        if preview is None:
            raise ValueError("规则修订缺少影响预览")
        basis = self._basis(revision, at)
        if _fingerprint(basis) != preview["fingerprint"]:
            old = json.loads(preview["snapshot"])["basis"]
            raise StalePreviewError(self._diff(old, basis, at))
        with self.connection:
            published = self.policies._apply(
                revision["jurisdiction"], revision["classification"], revision["purpose"], revision["decision"])
            self.connection.execute(
                "UPDATE rule_revisions SET state='published', published_at=?, published_revision=? WHERE id=?",
                (at, published, revision_id),
            )
            write(self.connection, at, actor, "policy.set", revision["jurisdiction"],
                  {"purpose": revision["purpose"], "revision": published, "staged": revision_id})
            write(self.connection, at, actor, "staging.publish", revision_id, {
                "jurisdiction": revision["jurisdiction"], "classification": revision["classification"],
                "purpose": revision["purpose"], "decision": revision["decision"],
                "published_revision": published, "preview": preview["id"],
            })
        return {"id": revision_id, "state": "published", "published_revision": published, "preview": preview["id"]}

    def _revision(self, revision_id):
        row = self.connection.execute("SELECT * FROM rule_revisions WHERE id=?", (revision_id,)).fetchone()
        if row is None:
            raise KeyError(revision_id)
        return dict(row)

    def _basis(self, revision, at):
        """采集预览所依据的事实：受影响产品的来源血缘、许可关系与已发布规则。"""
        jurisdiction, classification, purpose = revision["jurisdiction"], revision["classification"], revision["purpose"]
        products, assets, sources = [], {}, {}
        rows = self.connection.execute(
            "SELECT DISTINCT p.id,p.revision FROM products p "
            "JOIN product_inputs pi ON pi.product_id=p.id AND pi.product_revision=p.revision "
            "JOIN assets a ON a.id=pi.asset_id JOIN sources s ON s.id=a.source_id "
            "WHERE p.state='draft' AND s.jurisdiction=? AND s.classification=? ORDER BY p.id,p.revision",
            (jurisdiction, classification),
        ).fetchall()
        for row in rows:
            inputs = self.connection.execute(
                "SELECT a.id,a.state,a.source_id,s.owner,s.jurisdiction,s.classification,s.active "
                "FROM product_inputs pi JOIN assets a ON a.id=pi.asset_id JOIN sources s ON s.id=a.source_id "
                "WHERE pi.product_id=? AND pi.product_revision=? ORDER BY a.id",
                (row["id"], row["revision"]),
            ).fetchall()
            products.append({"id": row["id"], "revision": row["revision"], "inputs": [asset["id"] for asset in inputs]})
            for asset in inputs:
                assets[asset["id"]] = {"state": asset["state"], "source": asset["source_id"]}
                sources[asset["source_id"]] = {
                    "active": asset["active"], "owner": asset["owner"],
                    "jurisdiction": asset["jurisdiction"], "classification": asset["classification"],
                }
        recipients = [row[0] for row in self.connection.execute(
            "SELECT recipient FROM grants WHERE purpose=? UNION SELECT recipient FROM deliveries WHERE purpose=? ORDER BY 1",
            (purpose, purpose),
        )]
        permits = {
            source_id: {recipient: self.grants.permits(source_id, recipient, purpose, at) for recipient in recipients}
            for source_id in sorted(sources)
        }
        policies = {}
        keys = sorted({(source["jurisdiction"], source["classification"]) for source in sources.values()}
                      | {(jurisdiction, classification)})
        for jur, cls in keys:
            decision, revision_no = self.policies.decision(jur, cls, purpose)
            policies.setdefault(jur, {})[cls] = {purpose: [decision, revision_no]}
        return {
            "key": [jurisdiction, classification, purpose],
            "products": products, "assets": assets, "sources": sources,
            "recipients": recipients, "permits": permits, "policies": policies,
        }

    def _impacts(self, revision, basis):
        purpose = revision["purpose"]
        draft = (tuple(basis["key"]), revision["decision"])
        impacts = []
        for product in basis["products"]:
            for recipient in basis["recipients"]:
                before, _ = _evaluate(basis, product, recipient, purpose, None)
                after, details = _evaluate(basis, product, recipient, purpose, draft)
                if before == after:
                    continue
                impacts.append({
                    "product": product["id"], "product_revision": product["revision"],
                    "recipient": recipient, "purpose": purpose,
                    "change": "lose" if before else "gain",
                    "inputs": [
                        {key: detail[key] for key in
                         ("asset", "source", "owner", "jurisdiction", "classification",
                          "grant", "decision_before", "decision_after")}
                        for detail in details if detail["matches"]
                    ],
                })
        return impacts

    def _diff(self, old, new, at):
        changes = []
        for source_id in sorted(set(old["sources"]) | set(new["sources"])):
            before, after = old["sources"].get(source_id), new["sources"].get(source_id)
            if before is None:
                changes.append({"kind": "source", "change": "added", "source": source_id,
                                "message": "来源 {} 新纳入评估范围".format(source_id)})
            elif after is None:
                changes.append({"kind": "source", "change": "removed", "source": source_id,
                                "message": "来源 {} 已退出评估范围".format(source_id)})
            elif bool(before["active"]) != bool(after["active"]):
                deactivated = not after["active"]
                changes.append({"kind": "source", "change": "deactivated" if deactivated else "activated",
                                "source": source_id,
                                "message": "来源 {}{}".format(source_id, "已停用" if deactivated else "已重新启用")})
        for asset_id in sorted(set(old["assets"]) & set(new["assets"])):
            before, after = old["assets"][asset_id], new["assets"][asset_id]
            if before["state"] != after["state"]:
                changes.append({"kind": "asset", "change": "state", "asset": asset_id,
                                "from": before["state"], "to": after["state"],
                                "message": "记录 {} 状态由 {} 变为 {}".format(asset_id, before["state"], after["state"])})
        for source_id in sorted(set(old["permits"]) | set(new["permits"])):
            before_map = old["permits"].get(source_id, {})
            after_map = new["permits"].get(source_id, {})
            for recipient in sorted(set(before_map) | set(after_map)):
                before, after = before_map.get(recipient), after_map.get(recipient)
                if before != after:
                    changes.append(self._permit_change(source_id, recipient, before, after, at))
        for jur in sorted(set(old["policies"]) | set(new["policies"])):
            before_cls, after_cls = old["policies"].get(jur, {}), new["policies"].get(jur, {})
            for cls in sorted(set(before_cls) | set(after_cls)):
                before_purpose, after_purpose = before_cls.get(cls, {}), after_cls.get(cls, {})
                for purpose in sorted(set(before_purpose) | set(after_purpose)):
                    before, after = before_purpose.get(purpose), after_purpose.get(purpose)
                    if before != after:
                        changes.append({
                            "kind": "policy", "change": "decision",
                            "jurisdiction": jur, "classification": cls, "purpose": purpose,
                            "from": before, "to": after,
                            "message": "规则（{}/{}/{}）的已发布版本由 {} 变为 {}".format(
                                jur, cls, purpose, _format_policy(before), _format_policy(after)),
                        })
        before_products = {(p["id"], p["revision"]): p for p in old["products"]}
        after_products = {(p["id"], p["revision"]): p for p in new["products"]}
        for key in sorted(set(before_products) | set(after_products)):
            if key not in before_products:
                changes.append({"kind": "product", "change": "added", "product": key[0], "product_revision": key[1],
                                "message": "数据产品 {} 修订 {} 新纳入评估范围".format(key[0], key[1])})
            elif key not in after_products:
                changes.append({"kind": "product", "change": "removed", "product": key[0], "product_revision": key[1],
                                "message": "数据产品 {} 修订 {} 已退出评估范围".format(key[0], key[1])})
            elif before_products[key]["inputs"] != after_products[key]["inputs"]:
                changes.append({"kind": "product", "change": "inputs", "product": key[0], "product_revision": key[1],
                                "message": "数据产品 {} 修订 {} 的输入记录发生变化".format(key[0], key[1])})
        before_recipients, after_recipients = set(old["recipients"]), set(new["recipients"])
        for recipient in sorted(before_recipients ^ after_recipients):
            added = recipient in after_recipients
            changes.append({"kind": "recipient", "change": "added" if added else "removed", "recipient": recipient,
                            "message": "接收方 {}{}".format(recipient, "新纳入评估范围" if added else "已退出评估范围")})
        return changes

    def _permit_change(self, source_id, recipient, before, after, at):
        entry = {"kind": "permit", "source": source_id, "recipient": recipient, "from": before, "to": after}
        if before and not after:
            row = self.connection.execute("SELECT status,valid_until FROM grants WHERE id=?", (before,)).fetchone()
            if row is None:
                entry["change"] = "missing"
                entry["message"] = "接收方 {} 对来源 {} 的许可 {} 记录已不存在".format(recipient, source_id, before)
            elif row["status"] != "active":
                entry["change"] = "revoked"
                entry["message"] = "接收方 {} 对来源 {} 的许可 {} 已撤销".format(recipient, source_id, before)
            elif row["valid_until"] < at:
                entry["change"] = "expired"
                entry["message"] = "接收方 {} 对来源 {} 的许可 {} 已过有效期 {}".format(
                    recipient, source_id, before, row["valid_until"])
            else:
                entry["change"] = "replaced"
                entry["message"] = "接收方 {} 对来源 {} 的许可 {} 不再生效".format(recipient, source_id, before)
        elif after and not before:
            entry["change"] = "granted"
            entry["message"] = "接收方 {} 新获来源 {} 的许可 {}".format(recipient, source_id, after)
        else:
            entry["change"] = "replaced"
            entry["message"] = "接收方 {} 对来源 {} 的生效许可由 {} 变为 {}".format(recipient, source_id, before, after)
        return entry
