# Universal Watermark Disabler 2

このフォークは、Painter701氏の2015年版を、現在の Windows 10/11 向けに
再設計したものです。主UIには `Universal-TUI` を組み込んでいます。

> [!IMPORTANT]
> 現在は開発プレビューです。新しい Windows flight では、まず
> Diagnostics または Dry run を実行してください。対象を厳密に一意特定
> できない場合、何も変更せず終了します。

## 対象範囲

対象は Windows Insider / Evaluation のデスクトップ右下に表示される
ビルド文字列です。

- 「Windows のライセンス認証」透かしは削除しません。
- ライセンス状態や認証状態は変更しません。
- Test Mode、Safe Mode、Secure Boot、その他のセキュリティ警告は残します。
- Windows のシステムファイル、システムCOM登録、ACL、所有者は変更しません。

Windowsに公開された透かし無効化APIはありません。本ツールは非公開のShell実装を
扱うため、本質的にバージョン依存です。未知・曖昧・不一致の環境では必ず
fail-closed（無変更）になります。

## 2015年版からの主な変更

旧DelphiインストーラーとExplorerFrameプロキシは履歴参照用に残していますが、
新ビルドからは除外しました。

- Strict ISO C99準拠の単一コンソールEXEへ移行し、`Universal-TUI` を主UI化
- `RtlGetVersion` と `IsWow64Process2` でOS・x64/ARM64を正しく識別
- 現在のセッションのExplorerと、実際にロード中の `shell32.dll` を特定
- 一致するMicrosoft PDB GUID/ageと正確なsymbolを必須化し、ロード済みPEとディスク双方で検証
- x64構造スキャン候補を診断表示可能。ただしApplyには一切使用しない
- `PROCESS_ALL_ACCESS` を使わず、必要最小限のプロセス権限だけを要求
- 変更前の命令を保存し、PID・モジュールID・RVA・現在値が一致するときだけ復元
- メモリ保護属性とCFG call-target情報を維持し、命令キャッシュをflush
- ExplorerのDynamic Code Policyを検査し、保護機構は無効化しない
- 自動適用は `HKCU` の現在ユーザーだけに限定し、完全に削除可能

変更はExplorerのメモリ上だけです。Explorer再起動またはサインアウトで消えます。

## 対象とテスト計画

NT build 19041以降のnative x64/ARM64を対象にします。次は互換性の対象一覧であり、
各commitで全組み合わせを実機検証済みという意味ではありません。

- Windows 10 22H2 / ESU 19045、LTSC 2021 19044（x64）
- Windows 11 23H2 22631、24H2/LTSC 2024 26100、25H2 26200（x64/ARM64）
- Windows 11 26H1 28000系（入手可能なx64/ARM64実機）
- 262xx / 263xx / 280xx など並行する最新Insider系統

ビルド番号だけでは互換性を判定しません。最終判断には実際の
`shell32.dll`、PDB GUID/age、正確なsymbol、実行可能範囲、live bytesを
使います。Applyはx64/ARM64ともsymbols必須で、実験的なoffline候補は
x64の診断表示だけです。

## ビルド

Visual Studio 2022、Desktop development with C++、Windows 10/11 SDK、
CMake 3.24以降が必要です。

ソース言語の契約はStrict ISO C99です。GNU、およびGNU形式のClangでは言語拡張を無効化し、
`-std=c99 -pedantic-errors` でISO違反をエラーにします。MSVCにはC99モードが
ないため、Visual Studioビルドだけは最小の準拠Cフロントエンドとして
`/std:c11` を使用します。C99準拠の判定は専用MinGW CIが担当し、プロジェクト
自体はC11機能を使用しません。

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

ARM64は `-A ARM64` を指定します。GitHub ActionsではStrict ISO C99のMinGWビルドと
native MSVC x64/ARM64ビルドを実行します。すべてで境界値テスト、`shell32.dll` の
読み取り専用検査、正確なMicrosoft PDB symbol解決を実行します。リリース判定には、
対象Windows実機でのDiagnosticsとDry runが別途必要です。

## 使い方

Windows Terminalまたはconhostから `uwd.exe` を起動します。Actionと設定を選び、
**Save** で実行します。保存せずExitすればキャンセルです。

```text
uwd.exe --diagnostics
uwd.exe --apply --dry-run
uwd.exe --apply
uwd.exe --restore
uwd.exe --enable-startup
uwd.exe --disable-startup
```

最新InsiderでPDBがまだ公開されていない場合、Applyは安全に失敗します。
x64では保守者向けにheuristic候補だけを表示できます。

```text
uwd.exe --diagnostics --experimental-offline-scan
```

この候補がApplyに使われることはありません。開発時、Windows build 26300・
`shell32.dll` 26100.8951では、構造スキャンが「一意だがMicrosoft PDBと異なるRVA」
を返しました。この実測結果に基づき、正確なPDB identityを必須にしています。

Diagnosticsは必要に応じて正確なMicrosoft PDBをcacheします。`--offline` はsymbol serverへ
接続しません。`--dry-run` は既存cacheだけを使い、memory・registry・state・cacheを
変更しません。

設定とrollback情報は次に保存します。

```text
%LOCALAPPDATA%\UniversalWatermarkDisabler
```

rollback recordは整合性を検証し、interactive sessionごとに分離します。
multi-session Windowsでも別sessionの復元情報を上書きしません。

## Universal-TUI

`third_party/universal-tui` は `ayanami770/Universal-TUI` のcommit
`419fef2e89e68873fe969ecbdb02d8cfa2331ba3` を固定したvendored moduleです。
上流が現在privateのため、公開フォークとCIを再現可能にする目的でvendorしています。
Save成功時の任意終了とマウスExit伝播について、変更通知付きのlocal fixを含みます。
git submoduleへ変更する前に、この差分を上流へ反映する必要があります。

Universal-TUIはApache-2.0、本体はMITです。詳細は
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) を参照してください。
