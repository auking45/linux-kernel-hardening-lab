import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';

const basePrefix = process.env.BASE_PATH ?? (process.env.GITHUB_ACTIONS ? '/linux-kernel-hardening-lab' : '');

export default defineConfig({
  site: 'https://auking45.github.io',
  base: basePrefix || '/',
  prefetch: {
    prefetchAll: true,
    defaultStrategy: 'hover',
  },
  markdown: {
    remarkPlugins: [remarkMath],
    rehypePlugins: [rehypeKatex],
  },
  integrations: [
    {
      name: '@astrojs/sitemap',
      hooks: {},
    },
    starlight({
      title: 'Linux Kernel Hardening Lab',
      tagline: 'x86_64 & ARM64 Interactive Security Verification Lab',
      social: {
        github: 'https://github.com/auking45/linux-kernel-hardening-lab',
      },
      defaultLocale: 'root',
      locales: {
        root: {
          label: '한국어',
          lang: 'ko',
        },
        en: {
          label: 'English',
          lang: 'en',
        },
      },
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400..700;1,400..700&display=swap',
          },
        },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css',
          },
        },
        {
          tag: 'script',
          attrs: {
            src: `${basePrefix}/scripts/starlight-bridge.js`,
            defer: true,
          },
        },
      ],
      sidebar: [
            {
                  "label": "Getting Started",
                  "items": [
                        {
                              "label": "Overview",
                              "slug": "getting-started"
                        },
                        {
                              "label": "Dual-Arch Environment",
                              "slug": "getting-started/dual-arch"
                        }
                  ]
            },
            {
                  "label": "Principles",
                  "items": [
                        {
                              "label": "Curriculum Roadmap",
                              "slug": "principles"
                        },
                        {
                              "label": "Track 1. Program Execution Mechanics",
                              "items": [
                                    {
                                          "label": "01. Hello World Pipeline & ELF",
                                          "slug": "principles/01-hello-world-pipeline"
                                    },
                                    {
                                          "label": "02. Virtual Memory & Address Space",
                                          "slug": "principles/02-virtual-memory-layout"
                                    }
                              ]
                        },
                        {
                              "label": "Track 2. Process Memory & ABI",
                              "items": [
                                    {
                                          "label": "03. Stack Frame & Calling Convention",
                                          "slug": "principles/03-stack-frame-and-abi"
                                    }
                              ]
                        },
                        {
                              "label": "Track 3. Memory Exploitation Fundamentals",
                              "items": [
                                    {
                                          "label": "04. Shellcode Engineering",
                                          "slug": "principles/04-shellcode-engineering"
                                    },
                                    {
                                          "label": "05. Classic Stack BOF & RIP Hijacking",
                                          "slug": "principles/05-stack-bof-rip"
                                    }
                              ]
                        },
                        {
                              "label": "Track 4. Binary Architecture & Linking",
                              "items": [
                                    {
                                          "label": "06. Compilation & ELF File Format",
                                          "slug": "principles/06-compilation-and-elf"
                                    },
                                    {
                                          "label": "07. Symbols & Relocation Mechanics",
                                          "slug": "principles/07-symbols-and-linking"
                                    },
                                    {
                                          "label": "08. Static Linking & Binary Loading",
                                          "slug": "principles/08-static-linking-and-loading"
                                    },
                                    {
                                          "label": "09. Dynamic Linking & Runtime Loading",
                                          "slug": "principles/09-dynamic-linking-and-loading"
                                    }
                              ]
                        }
                  ]
            },
            {
                  "label": "Architecture",
                  "items": [
                        {
                              "label": "Memory & Protection Models",
                              "slug": "architecture"
                        }
                  ]
            },
            {
                  "label": "Attack Scenarios",
                  "items": [
                        {
                              "label": "Roadmap & Overview",
                              "slug": "scenarios"
                        },
                        {
                              "label": "01. Humanoid BOF & Stack Canary",
                              "slug": "scenarios/01-humanoid-bof"
                        },
                        {
                              "label": "02. ret2usr & SMEP/PXN Defense",
                              "slug": "scenarios/02-ret2usr"
                        },
                        {
                              "label": "03. ret2dir & SMAP/PAN Defense",
                              "slug": "scenarios/03-smap"
                        },
                        {
                              "label": "04. Heap UAF & SLAB Hardening",
                              "slug": "scenarios/04-heap-slab"
                        },
                        {
                              "label": "05. Control Flow Integrity (kCFI)",
                              "slug": "scenarios/05-kcfi"
                        },
                        {
                              "label": "06. Side-Channel Leaks (Spectre)",
                              "slug": "scenarios/06-spectre"
                        }
                  ]
            },
            {
                  "label": "Features",
                  "items": [
                        {
                              "label": "Taxonomy Roadmap",
                              "slug": "features"
                        },
                        {
                              "label": "01. Stack & Buffer Protection",
                              "items": [
                                    {
                                          "label": "Stack Canary",
                                          "slug": "features/01-stack-protector"
                                    },
                                    {
                                          "label": "Fortify Source",
                                          "slug": "features/02-fortify-source"
                                    },
                                    {
                                          "label": "Shadow Call Stack",
                                          "slug": "features/03-shadow-call-stack"
                                    },
                                    {
                                          "label": "STACKLEAK",
                                          "slug": "features/04-stackleak"
                                    }
                              ]
                        },
                        {
                              "label": "02. Memory Layout & Randomization",
                              "items": [
                                    {
                                          "label": "KASLR",
                                          "slug": "features/05-kaslr"
                                    },
                                    {
                                          "label": "FG-KASLR",
                                          "slug": "features/06-fgkaslr"
                                    },
                                    {
                                          "label": "Randomize Memory",
                                          "slug": "features/07-randomize-memory"
                                    }
                              ]
                        },
                        {
                              "label": "03. Memory Permissions & Access Separation",
                              "items": [
                                    {
                                          "label": "Strict Kernel RWX (W^X)",
                                          "slug": "features/08-strict-rwx"
                                    },
                                    {
                                          "label": "SMEP & PXN (ret2usr Defense)",
                                          "slug": "features/09-smep-pxn"
                                    },
                                    {
                                          "label": "SMAP & PAN (User Data Access Prevention)",
                                          "slug": "features/10-smap-pan"
                                    },
                                    {
                                          "label": "Page Table Check (Invalid Mapping Detection)",
                                          "slug": "features/11-page-table-check"
                                    },
                                    {
                                          "label": "KPTI (Kernel Page Table Isolation)",
                                          "slug": "features/12-kpti"
                                    }
                              ]
                        },
                        {
                              "label": "04. Control Flow Integrity (CFI)",
                              "items": [
                                    {
                                          "label": "Clang kCFI",
                                          "slug": "features/13-kcfi"
                                    },
                                    {
                                          "label": "x86 IBT & Shadow Stack",
                                          "slug": "features/14-ibt-shstk"
                                    },
                                    {
                                          "label": "ARM64 BTI & PAC",
                                          "slug": "features/15-bti-pac"
                                    }
                              ]
                        },
                        {
                              "label": "05. Heap & Slab Allocator Hardening",
                              "items": [
                                    {
                                          "label": "SLAB Freelist Hardening",
                                          "slug": "features/16-slab-freelist"
                                    },
                                    {
                                          "label": "Heap Zeroing (Alloc & Free)",
                                          "slug": "features/17-heap-init"
                                    },
                                    {
                                          "label": "Hardened Usercopy",
                                          "slug": "features/18-hardened-usercopy"
                                    },
                                    {
                                          "label": "KFENCE (Memory Safety Detector)",
                                          "slug": "features/19-kfence"
                                    }
                              ]
                        },
                        {
                              "label": "06. Structure & Compiler Level Protections",
                              "items": [
                                    {
                                          "label": "Structleak (Stack Auto-Initialization)",
                                          "slug": "features/20-structleak"
                                    },
                                    {
                                          "label": "Randstruct (Structure Layout Randomization)",
                                          "slug": "features/21-randstruct"
                                    }
                              ]
                        },
                        {
                              "label": "07. Speculative Execution Defenses",
                              "items": [
                                    {
                                          "label": "Spectre v1 (array_index_nospec)",
                                          "slug": "features/22-spectre-v1"
                                    },
                                    {
                                          "label": "Spectre v2 (Retpoline, IBPB, STIBP)",
                                          "slug": "features/23-spectre-v2"
                                    },
                                    {
                                          "label": "Speculative Store Bypass Disable (SSBD)",
                                          "slug": "features/24-ssbd"
                                    },
                                    {
                                          "label": "MDS & TAA Mitigation (VERW)",
                                          "slug": "features/25-mds"
                                    }
                              ]
                        },
                        {
                              "label": "08. Mandatory Access Control & LSM Framework",
                              "items": [
                                    {
                                          "label": "Stackable LSM Architecture",
                                          "slug": "features/26-lsm-stacking"
                                    },
                                    {
                                          "label": "AppArmor Process Isolation",
                                          "slug": "features/27-apparmor"
                                    },
                                    {
                                          "label": "SELinux Type Enforcement",
                                          "slug": "features/28-selinux"
                                    },
                                    {
                                          "label": "Landlock Unprivileged Sandboxing",
                                          "slug": "features/29-landlock"
                                    }
                              ]
                        },
                        {
                              "label": "09. System & Binary Integrity Verification",
                              "items": [
                                    {
                                          "label": "IMA Integrity Measurement",
                                          "slug": "features/30-ima"
                                    },
                                    {
                                          "label": "EVM Metadata Protection",
                                          "slug": "features/31-evm"
                                    },
                                    {
                                          "label": "IPE Policy Enforcement",
                                          "slug": "features/32-ipe"
                                    },
                                    {
                                          "label": "Kernel Lockdown LSM",
                                          "slug": "features/33-lockdown"
                                    },
                                    {
                                          "label": "Module Signature Verification",
                                          "slug": "features/34-module-sig"
                                    }
                              ]
                        },
                        {
                              "label": "10. Attack Surface Reduction & System Hardening",
                              "items": [
                                    {
                                          "label": "Seccomp-BPF Syscall Filtering",
                                          "slug": "features/35-seccomp"
                                    },
                                    {
                                          "label": "BPF Hardening & JIT Blinding",
                                          "slug": "features/36-bpf-hardening"
                                    },
                                    {
                                          "label": "Strict Devmem & Strict I/O",
                                          "slug": "features/37-strict-devmem"
                                    },
                                    {
                                          "label": "Kernel Info Leaks & Dmesg Restrict",
                                          "slug": "features/38-info-leaks"
                                    },
                                    {
                                          "label": "Yama LSM Ptrace Scope",
                                          "slug": "features/39-yama-ptrace"
                                    },
                                    {
                                          "label": "Kexec Restrictions",
                                          "slug": "features/40-kexec-restrict"
                                    }
                              ]
                        },
                        {
                              "label": "11. Modern ARMv8/ARMv9 & Mobile Security",
                              "items": [
                                    {
                                          "label": "ARM64 Memory Tagging (MTE)",
                                          "slug": "features/41-arm64-mte"
                                    },
                                    {
                                          "label": "ARMv9 Permission Overlay (POE)",
                                          "slug": "features/42-armv9-poe"
                                    },
                                    {
                                          "label": "Android Virtualization (AVF/pKVM)",
                                          "slug": "features/43-avf-pkvm"
                                    },
                                    {
                                          "label": "Arm Confidential Compute (CCA)",
                                          "slug": "features/44-arm-cca"
                                    }
                              ]
                        }
                  ]
            }
      ],
    }),
  ],
});
