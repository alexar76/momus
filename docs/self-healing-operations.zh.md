# 运行自愈回路：密钥、配置项，以及改动后需要重新部署什么

> 🌐 [English](self-healing-operations.md) · [Русский](self-healing-operations.ru.md) · [Español](self-healing-operations.es.md) · [Français](self-healing-operations.fr.md) · **中文**

> **切换为自行合并** —— 一个复选框，附流程图：[switch-to-auto-merge.zh.md](switch-to-auto-merge.zh.md)。

> **端到端已验证** —— 训练靶子、三次演练，以及修复为何先到生产、后到 `main`：[proving-the-loop.zh.md](proving-the-loop.zh.md)。

> **是什么拦下一个坏补丁** —— 无人值守的修复要经过的每一道防护，以及每一道背后的事故：[autonomous-repair-guards.zh.md](autonomous-repair-guards.zh.md)。

MOMUS 发现缺陷，AI-Factory 编写补丁，机群完成构建，MOMUS 通过部署闸门放行，节点智能体上线，出现回归则回滚。本页是运维一侧的说明：哪个服务跑在哪里、哪个环境变量触发哪一类拒绝，以及催生本页的那个问题——**改动代码时到底要重新部署几样东西。**

## 关于重新部署的简短答案

**一个。** 不是两个工厂。

补丁编写路由（`POST /api/remediation/fix`）**只**在 `AIFACTORY_REMEDIATION_FIX_ENABLED=1` 的实例上挂载。公开实例并未设置该变量，因此那里根本不存在这个路由——不是「存在但拒绝」。这个区别是刻意的：`web/frontend/next.config.js` 会把 `/api/:path*` 重写到内部 API，所以一个仅被禁用的路由依然是一个可从公网访问、返回 403 的端点：白白多出的攻击面。

因此：

| 你改了什么 | 你要重新部署什么 |
|---|---|
| `web/backend/api/remediation.py`、`web/backend/services/remediation_fix.py` | 仅 **修复实例** |
| `skopos/skopos/remediation/*` | **指挥者**（`skopos-remediation`） |
| `momus/momus/*` | **momus-backend** |
| 节点智能体的构建/部署代码 | 每台机群主机上的 **智能体** |
| 共用的 `core/`、`llm/` | 你真正关心的那些实例——这一点对本仓库中每个卫星系统本来就成立，自愈回路并未改变它 |

公开工厂不执行修复流程，所以修复相关的改动不会影响它。

## 两种模式

被闭环照看的每个组件都处于两种模式之一，差别只在最后一步。开头完全相同：MOMUS 探测、确认发现、
签署修复工单，指挥者驱动工厂撰写补丁，补丁以可复核的 diff 落到 `momus/fix-…` 分支上。

**自动修复。** 该组件的部署之手构建该分支，MOMUS 对候选实例重跑探针，只有签名的 `fixed` 裁定
才会提升镜像并重建服务。不惊动任何人。这是给「已安装之手、且该手能构建其镜像」的组件用的模式。

**仅出补丁。** 上述一切照常发生，唯独少了最后一步：分支已就绪，任务在等待。由人复核 diff 并
发布。这不是降级模式——凡是「手无物可提升」的地方，它就是正确的模式；凡是你希望在补丁运行前
先读一遍的地方，也应当选它。

一个组件处于哪种模式，是它部署方式的属性，而不是需要记住的开关：

| 组件 | 模式 | 原因 |
|---|---|---|
| 金丝雀 | 自动修复 | 闭环的试验场；它存在的意义就是被弄坏再修好 |
| gaia | 自动修复 | 自有 compose 项目，从本仓库构建 |
| hub（生产） | 自动修复 | 它的手可达舰队中继；见*谁跑在哪里* |
| oracles | 仅出补丁 | 从另一份检出构建，任何手都无法产出它的镜像 |
| MOMUS、Treasury、SKOPOS、闸门 | 都不是 | 在代码中被拒绝——见*约束边界* |

**把某个组件切到仅出补丁**是它那只手的属性，共三级手段，由轻到重：

* `SKOPOS_AGENT_DRY_RUN=1` —— 手会验证指令并打印它本会执行的命令。上游一切照旧，因此这是
  「想让闭环跑一遍但什么都不动」时该用的模式。
* `SKOPOS_AGENT_SERVICE_ALLOWLIST=`（留空）—— 手拒绝一切指令。用于停用单台主机而不影响舰队。
* `systemctl stop skopos-deploy-hand@<组件>` —— 指令堆积在指挥者处并最终过期。

**把整个闭环切过去**：在指挥者上设 `SKOPOS_REMEDIATION_DRY_RUN=1` —— 发现、工单与补丁照旧，
但永不下达指令。

没有任何开关能把「无手」的组件从仅出补丁变成自动修复。这是刻意的：一个组件之所以可被自动修复，
是因为它有地方可供部署，而不是因为它被标记成那样。

## 谁跑在哪里

| 角色 | 服务 | 监听 |
|---|---|---|
| 发现缺陷，并充当 **部署闸门** | `momus-backend` | loopback |
| 支付赏金（MOMUS 从不持有的独立密钥） | `momus-treasury` | loopback |
| 指挥一次修复任务 | `skopos-remediation` | loopback |
| 编写补丁 | 工厂的修复实例 | loopback |
| git 远端（既是传输通道，**也是**审计痕迹） | Gitea `alexar76/aicom` | loopback（`:3000` HTTP、`:2222` SSH） |
| 构建并上线 | 目标主机上的节点智能体 | 仅出向，不开端口 |
| 第一个被弄坏又被修好的对象 | `momus-canary` | loopback |

这里没有任何东西会在机群主机上开放入向端口。智能体主动轮询；没人调用它。

## 整条链路，以及每一步存在的理由

```
MOMUS 发现 ──已签名工单（A2A）──▶ 指挥者
  ├─ 1. 工厂编写统一 DIFF              （从不产出镜像；它不负责构建）
  ├─ 2. 指挥者提交并推送 momus/fix-<finding_id>
  │        该分支既是送往构建方的传输通道，也是供人审阅的产物
  ├─ 3. 已签名的构建指令指明一个 COMMIT   （从不内联源码）
  │        智能体：取回该提交，拒绝任何不在它「自己」前缀清单内的分支，拒绝并非该分支顶端的
  │        提交，按它「自己」的配方构建，回报镜像摘要，并启动 <服务>-candidate，
  │        以便闸门有东西可以探测
  ├─ 4. MOMUS 探测「候选构建」            （晋级前，与该摘要绑定）
  ├─ 5. 已签名的部署指令携带该摘要
  │        智能体：记录当前运行的摘要，把 compose 标签移到新摘要上，重建容器，
  │        通过健康门控，并核实容器里「确实」是那个摘要
  ├─ 6. MOMUS 复检「线上」服务
  └─ 7. 若仍能复现 → 已签名的回滚指令 → 智能体恢复它记录下的那个摘要
```

有两处遗漏曾让这一切成为表演，值得记住，因为当时的症状极具误导性：

* **没有任何环节构建镜像。** 于是「部署」只是用主机上已有的镜像重建容器，闸门检查的恰恰是它本应替换掉的那个构建，理所当然地回答「仍能复现」，而升级流程却把责任归给了补丁。
* **`DeployOrder.image` 根本无人读取。** 这个字段存在，也带着值。

## 约束边界：指令说「哪一个」，主机说「允许什么」

下面每一条约束都由 **智能体** 依据其本地配置执行。调用方无法扩大其中任何一条。

* 智能体只构建和部署自己 `SKOPOS_AGENT_SERVICE_ALLOWLIST` 内的服务；
* 只从匹配自己 `SKOPOS_AGENT_BRANCH_PREFIXES` 的分支构建；
* 只用自己 `SKOPOS_AGENT_BUILD_MAP` 中的 Dockerfile 与上下文构建；
* 只部署**它自己构建的、且属于同一服务的**镜像（比对它自己的构建日志）——因此指明主机上任何其他镜像的指令都解析不到任何东西；
* 拒绝依据一份检查了「线上」服务的裁决去晋级新镜像。`gated` 位于已签名的 FixVerdict 之内，因此无法在传输途中被重新贴标；
* 回滚指令**完全不携带镜像**：它指明一条先前的指令，目标取自智能体记录下的、那次部署之前正在运行的内容。所以回滚通道无法投送任何新东西，也正因如此它可以不需要正向部署所必须的 MOMUS 裁决（回滚发生的时刻，恰恰就是那份裁决被证明有误的时刻）。

`main` 在服务端受保护，**并且**指挥者拒绝推送到自己分支前缀之外。两道独立策略，因为其中一道配置失误不应就足以突破。

> **在信任它之前先核实。** `alexar76/aicom` 上 `main` 的保护目前是 `enable_push=true`，白名单为 `['alexar76']`。也就是说，任何以该用户身份推送的东西都能直达 `main`。请使用按仓库授权的 **部署密钥**推送，而不是用户级访问令牌（Gitea 令牌属于用户：`write:repository` 覆盖该所有者的全部仓库）。`push_whitelist_deploy_keys` 为 `false`，所以部署密钥无法触及 `main`。
>
> 关于如何证明这一点：在安装了 Gitea Actions 执行器的主机上，**不要**用真的向 `main` 推送来测试——推送到 `main` 可能触发部署工作流。改为读取保护配置。

## 配置项

### 工厂的修复实例

| 变量 | 默认 | 作用 |
|---|---|---|
| `AIFACTORY_REMEDIATION_FIX_ENABLED` | 未设置 | **总开关。** 未设置 ⇒ 该路由完全不挂载。 |
| `AIFACTORY_REMEDIATION_KEY` | 未设置 | 与指挥者的共享密钥。生产环境必填；生产环境未设置 ⇒ 返回 503，绝不放开。 |
| `AIFACTORY_REMEDIATION_MOMUS_PUBKEY` | 未设置 | MOMUS 的 Ed25519 公钥。缺少它则工单无法验证，任何请求都被拒绝。 |
| `AIFACTORY_REMEDIATION_SCOPE` | 金丝雀 + hub | JSON `{组件: [路径]}`。该组件的补丁**唯一**可以触及的文件。模型若返回清单之外的路径，一律拒绝。Hub 仅限 `aimarket-hub/aimarket_hub/unpaid_invoke.py`。MOMUS / Treasury / 闸门不在其中。 |
| `AIFACTORY_REMEDIATION_LLM_BUDGET_S` | `240` | 该路由索取文件的完整内容，因此耗时以分钟计而非秒。必须**低于**指挥者客户端的超时。 |
| `AIFACTORY_DEMO_READONLY` | — | 若为 `1`，拒绝编写补丁：这是公开演示实例的守卫，而公开演示实例并不是自主补丁器应该待的地方。 |

### 指挥者

| 变量 | 默认 | 作用 |
|---|---|---|
| `SKOPOS_REMEDIATION_ENABLED` | `1` | 总开关。`0` ⇒ 永不签署任何部署指令。 |
| `SKOPOS_REMEDIATION_DRY_RUN` | `0` | `1` ⇒ 链路照常走完，但不签署任何会真正上线的东西。而且如实说明：任务结束时会声明什么都没有部署。真实模式（`0`）是 canary + hub 的默认。 |
| `SKOPOS_FACTORY_URL` | 未设置 | 在**真实模式下**未设置属于配置故障，而非回退默认值：过去这会导致合成出一个假补丁。 |
| `SKOPOS_MOMUS_PUBKEY` | 未设置 | 非 dry-run 时必填：无法验证的工单一律拒绝。 |
| `SKOPOS_GIT_REPO_URL` / `SKOPOS_GIT_SSH_KEY` | 未设置 | 修复分支的远端及其凭据（一把部署密钥）。 |
| `SKOPOS_FIX_BRANCH_PREFIX` | `momus/fix-` | 同时也是指挥者拒绝越出的推送前缀。 |
| `SKOPOS_AGENT_TOKEN` | 未设置 | 部署之手出示的注册令牌。缺少它，指挥者在非 dry-run 下不派发任何指令（失效即关闭），部署之手会一直收到 503。 |
| `SKOPOS_DEPLOY_RESULT_TIMEOUT_S` | `420` | 等待智能体回报的时长。必须超过它的轮询间隔 + compose 超时 + 健康等待。 |
| `SKOPOS_MAX_DEPLOYS_PER_DAY` | `6` | 限流。达到上限 ⇒ 拒绝，熔断器**不会**跳闸。 |
| `SKOPOS_MAX_DEPLOYS_PER_COMPONENT_PER_DAY` | `2` | 反复重新部署同一个服务是抖动，不是修复。 |
| `SKOPOS_MAX_ROLLBACKS` | `2` | **真正要紧的信号。** 窗口内两次回滚 ⇒ 熔断器跳闸。 |
| `SKOPOS_MAX_ROLLBACK_RATE` | `0.34` | 需配合 `SKOPOS_BREAKER_MIN_SAMPLE`（`5`），因为一比一并不等于 100% 失败率。 |
| `SKOPOS_MAX_CONSECUTIVE_FAILURES` | `3` | 修不好的组件，交给人。 |
| `SKOPOS_OPERATOR_TOKEN` | 未设置 | 清除已跳闸的熔断器所必需。未设置 ⇒ 没人能清除，而这是安全的方向。 |

### 节点智能体

| 变量 | 默认 | 作用 |
|---|---|---|
| `SKOPOS_AGENT_DRY_RUN` | `0` | `1` ⇒ 校验并打印将要执行的命令，但不执行任何操作。真实模式（`0`）是默认。 |
| `SKOPOS_AGENT_SERVICE_ALLOWLIST` | `canary,hub` | 逗号分隔。未设置 ⇒ canary + hub（及其 compose 别名）。为空 ⇒ 智能体什么都动不了。MOMUS / Treasury 不在清单上。 |
| `SKOPOS_AGENT_BRANCH_PREFIXES` | `momus/fix-` | 本地配置。从 `main` 构建等于构建别人最后合并进去的任何东西。 |
| `SKOPOS_AGENT_BUILD_MAP` | `{}` | JSON `{服务: {dockerfile, context, image_ref, network, compose_service}}`。没有配方 ⇒ 拒绝构建该服务。**当组件名与 compose 服务名不同时，`compose_service` 是必填的**——MOMUS 把它的目标叫作 `canary`，而 compose 服务是 `momus-canary`，缺少该映射时每次部署都会指向一个并不存在的服务。 |
| `SKOPOS_AGENT_REPO_URL` | 未设置 | 源码允许来自何处。绝不从指令中读取。 |
| `SKOPOS_AGENT_HEALTH_WAIT_S` | `20` | 给容器多长时间证明自己没有在崩溃重启循环中。`compose up` 以 0 退出并不构成裁决。 |

## 观察它，以及让它停下

* `GET /remediation/health` —— 各项数字，外加熔断器的状态与阈值。
* `GET /metrics` —— Prometheus。真正值得告警的是 **`skopos_remediation_rollback_rate`**：每个已上线补丁对应的回滚数，也就是闸门的裁决与现实相互背离的频率。被闸门拒绝的补丁不花任何代价；已经上线又不得不撤回的补丁才是危险的形态。
* `GET /api/remediation/stats` —— LOGOS 读取的摘要。不要重命名它的键。
* `POST /remediation/breaker/clear` 携带 `x-skopos-operator` —— 重新武装已跳闸熔断器的**唯一**途径。代码中没有任何东西会清除它：一个重启即自动复位的熔断器，恰会被它本要打断的那个崩溃循环所击败，而「它自己恢复了」与「没人知道出过事」无法区分。跳闸状态可跨重启存续，状态文件不可读时按关闭态处理。

## 启用顺序（可辩护的那一种）

1. 在**私有**实例上设置 `AIFACTORY_REMEDIATION_*`，并确认 `GET /api/remediation/fix/status` 显示 `enabled: true` 以及你预期的作用范围。
2. 给指挥者配好 git 凭据，并在信任它之前**证明 `main` 会拒绝推送**。
3. 运行节点智能体。默认即为真实部署：`SKOPOS_AGENT_DRY_RUN=0` 且 `SKOPOS_AGENT_SERVICE_ALLOWLIST=canary,hub`。MOMUS / Treasury 不在清单上。
4. 确认 `/remediation/health` 显示 dry-run 已关闭，且智能体正在领取指令。
5. 刻意弄坏金丝雀，观察回路把它修好并重新部署，并阅读它推送出来的那个分支。
6. Hub 已在同一条路上。`fixed` 裁决仍然不会合并进 `main`。
7. 若要暂停：设 `SKOPOS_AGENT_DRY_RUN=1` 和 `SKOPOS_REMEDIATION_DRY_RUN=1`，或清空允许清单。

针对安全内核（MOMUS、Treasury、闸门自身）的发现完全不走这条路：`escalation_for` 会把它们导向人工治理外加一个独立运营的验证方，因为一个自我修复的审计者等于给自己的工作签了合格证。
