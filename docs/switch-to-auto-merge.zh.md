# 让闭环自己合并进 `main`

> 🌐 [English](switch-to-auto-merge.md) · [Русский](switch-to-auto-merge.ru.md) · [Español](switch-to-auto-merge.es.md) · [Français](switch-to-auto-merge.fr.md) · **中文**

代码已完成并已启用。**剩下的只有 Gitea 里的一个复选框。**

## 要做什么

1. Gitea → **`aicom`** 仓库 → **Settings → Branches**
2. 打开 **`main`** 的保护规则
3. 勾选 **Whitelist Deploy Keys**
4. 保存

之后被允许的那把密钥——指挥者的，且仅它一把：

```
SHA256:aiTxt4Fy0PAtQXx6f8eCt38EUswyeQmVbPHP2Y9DwJU
skopos-remediation-conductor@oracle-host
```

指挥者上已经配好，那边无需改动：

```
SKOPOS_EXPERIMENTAL_AUTO_MERGE=1
SKOPOS_DEFAULT_BRANCH=main
```

### 确认是否生效

```bash
docker exec skopos-remediation python3 -c "
from skopos.remediation.git_push import GitPusher
p = GitPusher()
r = p.merge_to_main(finding_id='<一个到达 DONE 的发现>',
                    branch='momus/fix-<id>-<n>', component='praxis')
print(r.ok, r.error or r.details)"
```

`ok: True` 表示切换已生效。`Not allowed to push to protected branch main` 表示 Gitea 还没改。

## 会改变什么

```mermaid
flowchart LR
    subgraph NOW["现在"]
        direction TB
        A1["任务到达 DONE"] --> B1["指挥者尝试合并"]
        B1 --> C1["Gitea 拒绝<br/>部署密钥"]
        C1 --> D1["修复分支等待"]
        D1 --> E1["你运行<br/>pull_momus_fixes.sh"]
        E1 --> F1["main 已更新"]
    end
    subgraph AFTER["勾选之后"]
        direction TB
        A2["任务到达 DONE"] --> B2["指挥者自行合并"]
        B2 --> C2["在 main 上<br/>merge --no-ff"]
        C2 --> F2["main 已更新"]
        F2 -.->|"若不对"| G2["git revert -m 1"]
    end
    NOW ~~~ AFTER
```

仅此而已。其余一切不变：合并仍是 `--no-ff`，遇冲突仍中止，仍绝不强推，且**只**对到达 `DONE` 的任务运行。

## 代价是什么，以及如何撤销

| | |
|---|---|
| **今天**被盗的指挥者密钥只能 | 创建一个没人合并的修复分支 |
| **之后**它就能 | 写入 `main`——**仅限本仓库**（部署密钥按仓库生效） |
| **不要**改用账户令牌 | Gitea 令牌是用户级的：会触及该账户拥有的所有仓库 |

三条彼此独立的退路，任一即可：

* 在 Gitea 里取消勾选；
* 指挥者上设 `SKOPOS_EXPERIMENTAL_AUTO_MERGE=0`；
* `git revert -m 1 <提交>` —— 该命令就写在合并提交自己的消息里。

## 为什么这是一个独立开关

指挥者的代码在除一条之外的所有路径上都拒绝 `main`，正是这道拒绝让被盗凭据成为麻烦而不是事故。
Gitea 的分支保护是针对同一件事的**第二道、独立的**策略。启用合并意味着决定解除第二道——因此它是
你去勾的复选框，而不是闭环能给自己设的变量。

## 修复本身如何运作

每个菱形都是一个拒绝点。无法作答的一步会停下并把任务留给人；它绝不猜测。

```mermaid
flowchart TD
    A["MOMUS 每 900 秒<br/>扫描一个靶子"] --> B{"有发现吗？"}
    B -->|没有| A
    B -->|有| C["第二个 MOMUS 实例，<br/>独立密钥：重跑探测<br/>+ 交叉核对契约"]
    C --> D{"两次解读<br/>都认为确有其事？"}
    D -->|否| X1["不确定 ——<br/>不算作证据"]
    D -->|是| E{"自动驾驶策略：<br/>严重度 · 观测次数<br/>冷却 · 每日上限"}
    E -->|拒绝| X2["记录在案，留给人处理"]
    E -->|派发| F["AI-Factory：修复者在<br/>1–3 个已声明文件内写补丁<br/>凭据不可读"]
    F --> G["提交到修复分支<br/>绝不 main · 绝不 --force"]
    G --> H["构建指令：<br/>从该提交构建镜像"]
    H --> I{"组件自己的<br/>测试通过了吗？"}
    I -->|否| X3["构建被阻止，<br/>失败输出送入下一次尝试"]
    I -->|是| J["候选容器，<br/>不发布任何端口"]
    J --> K{"晋级前闸门：<br/>MOMUS 探测候选"}
    K -->|仍然复现| X4["拒绝部署"]
    K -->|已修好| L["指挥者签署部署指令，<br/>其中携带 MOMUS 的裁定"]
    L --> M{"节点智能体校验：<br/>两个签名<br/>+ 它自己的服务白名单"}
    M -->|否| X5["部署之手拒绝"]
    M -->|是| BR{"熔断器：<br/>部署 · 回滚<br/>连续失败"}
    BR -->|"被节流"| X6["部署被扣下：<br/>反复折腾不是修复"]
    BR -->|"预算之内"| N["晋级镜像"]
    N --> O{"部署闸门就地执行，<br/>在安装之后"}
    O -->|复现| P["回滚指令，<br/>立即执行"]
    O -->|干净| Q["DONE"]
    Q --> R["合并 —— 今天是你，<br/>勾选之后是指挥者"]
```

运行期间值得知道的两件事：

* **第 1、2 次尝试用修复者，第 3 次用 METIS 议会** —— 任务转交给人之前的最后一道
  （`AIFACTORY_REMEDIATION_COUNCIL_FROM_ATTEMPT=3`）。一次议会审议的花费约为一次普通尝试的 16 倍，
  所以它排第三而不是第一。
* **只要修复分支未合并，从 `main` 的重新构建就会静默回退修复。** 这正是应当认真对待那个复选框、
  而不是把分支留在队列里的实际原因。

## 相关

* [self-healing-operations.zh.md](self-healing-operations.zh.md) —— 密钥、配置、要重新部署什么
* [autonomous-repair-guards.zh.md](autonomous-repair-guards.zh.md) —— 每一道关卡及其背后的事故
* [proving-the-loop.zh.md](proving-the-loop.zh.md) —— 训练靶子与三次经过验证的演练
