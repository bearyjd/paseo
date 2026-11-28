import { expect, test } from "../support/fixtures";
import { openAgentRoute, seedMockAgentWorkspace } from "../support/helpers/mock-agent";
import { clickSettingsBackToWorkspace, openSettingsSection } from "../support/helpers/settings";

test("applies the content font size to an already-open chat", async ({ page }) => {
  test.setTimeout(120_000);
  const agent = await seedMockAgentWorkspace({ repoPrefix: "chat-font-size-", title: "Font size" });
  try {
    const prompt = "Existing message for the font size check";
    await agent.client.sendAgentMessage(agent.agentId, prompt);
    await agent.client.waitForFinish(agent.agentId, 30_000);
    await openAgentRoute(page, agent);

    const userMessage = page.getByTestId("user-message").getByText(prompt, { exact: true });
    const assistantText = page.getByTestId("assistant-message").first().locator("p").first();
    await expect(userMessage).toHaveCSS("font-size", "14px", { timeout: 30_000 });
    await expect(assistantText).toHaveCSS("font-size", "14px");
    const timeOrigin = await page.evaluate(() => performance.timeOrigin);

    await page.getByTestId("sidebar-settings").filter({ visible: true }).first().click();
    await openSettingsSection(page, "appearance");
    const size = page.getByRole("textbox", { name: "Content font size", exact: true });
    await size.fill("21");
    await size.press("Tab");
    await expect(size).toHaveValue("21");
    await clickSettingsBackToWorkspace(page);

    await expect(userMessage).toBeVisible();
    await expect(assistantText).toBeVisible();
    expect(await page.evaluate(() => performance.timeOrigin)).toBe(timeOrigin);
    await expect(userMessage).toHaveCSS("font-size", "21px");
    await expect(assistantText).toHaveCSS("font-size", "21px");
  } finally {
    await agent.cleanup();
  }
});
