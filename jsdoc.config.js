module.exports = {
	"tags": {
		"allowUnknownTags": true
	},
	"source": {
		"include": ["./src"],
		"excludePattern": "node_modules|test"
	},
	"plugins": ["plugins/markdown"],
	"markdown": {
		// JSDoc writes `lang-js`; clean-jsdoc-theme only reads `language-js`
		highlight: (code, language) => {
			const escaped = code
				.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;');
			const lang_class = language ? ` class="language-${language}"` : '';
			return `<pre><code${lang_class}>${escaped}</code></pre>`;
		}
	},
	"opts": {
		"recurse": true,
		"destination": "./jsdoc",
		"template": "node_modules/clean-jsdoc-theme/dist",
		"siteName": "@control/jwt",
		"readme": "./README.md",
		"customJsFile": "./docs/scripts/version-selector.js",
		"siteUrl": process.env.SITE_URL || '',
		"basePath": process.env.JSDOC_BASE_PATH || '',
		"meta": [{
			"name": "docs_version",
			"value": process.env.VERSION
		}, {
			"name": "base_path",
			"value": process.env.JSDOC_BASE_PATH
		}],
		"menu": [
			{ "title": "Home", "link": "/", "target": "_self", "icon": "lucide:home" }
		]
	},
	"templates": {
		"default": {
			// needed for syntax highlighting
			"outputSourceFiles": true
		}
	}
};
