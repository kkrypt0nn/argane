// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightAutoSidebar from "starlight-auto-sidebar";
import starlightBlog from "starlight-blog";
import starlightFullViewMode from "starlight-fullview-mode";

// https://astro.build/config
export default defineConfig({
  site: "https://argane.krypton.ninja",
  integrations: [
    starlight({
      title: "Argane",
      favicon: "public/assets/logo_light.png",
      editLink: {
        baseUrl: "https://github.com/kkrypt0nn/argane/edit/main/www/",
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/kkrypt0nn/argane",
        },
      ],
      sidebar: [
        {
          label: "Introduction",
          collapsed: false,
          items: [{ autogenerate: { directory: "introduction" } }],
        },
        {
          label: "Guides",
          collapsed: true,
          items: [{ autogenerate: { directory: "guides" } }],
        },
        {
          label: "Commands",
          collapsed: true,
          items: [{ autogenerate: { directory: "commands" } }],
        },
        {
          label: "Rules",
          collapsed: true,
          items: [{ autogenerate: { directory: "rules" } }],
        },
        {
          label: "Frequently Asked Questions",
          collapsed: true,
          items: [{ autogenerate: { directory: "faq" } }],
        },
        {
          label: "GitHub",
          link: "https://github.com/kkrypt0nn/argane",
        },
      ],
      plugins: [
        starlightAutoSidebar(),
        starlightBlog({
          authors: {
            krypton: {
              name: "Krypton",
              title: "Maintainer",
              picture: "https://github.com/kkrypt0nn.png",
              url: "https://krypton.ninja",
            },
          },
          metrics: {
            readingTime: true,
            words: "total",
          },
        }),
        starlightFullViewMode(),
      ],
    }),
  ],
});
