"use client";

import React, { useState, useEffect } from "react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "@/lib/store/toast-store";
import { apiClient } from "@/lib/api/client";
import {
  UserGroupIcon,
  BookmarkIcon,
  ChatBubbleLeftRightIcon,
  ArrowUpRightIcon,
  PlusIcon,
} from "@heroicons/react/24/outline";

export default function PenHubPage() {
  const [posts, setPosts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showPublishForm, setShowPublishForm] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newSummary, setNewSummary] = useState("");
  const [newCategory, setNewCategory] = useState("Offensive Research");
  const [publishing, setPublishing] = useState(false);

  const fetchPosts = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get("/v1/pen-hub/posts");
      if (res.data?.data) {
        setPosts(res.data.data);
      }
    } catch (e) {
      console.error("Failed to load pen-hub posts:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPosts();
  }, []);

  const handlePublish = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newSummary) {
      toast.error("Validation Error", "Please provide both a title and summary.");
      return;
    }
    setPublishing(true);
    try {
      await apiClient.post("/v1/pen-hub/posts", {
        title: newTitle,
        summary: newSummary,
        category: newCategory,
        tags: ["Community", "Playbook", "Defense"],
        author: "Operator",
      });
      toast.success("Playbook Published", "Your playbook is now live on Pen Hub.");
      setNewTitle("");
      setNewSummary("");
      setShowPublishForm(false);
      await fetchPosts();
    } catch {
      toast.error("Publish Failed", "Unable to distribute playbook.");
    } finally {
      setPublishing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#1e293b] pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-xl bg-gradient-to-b from-[#162032] to-[#070b14] border border-cyber-cyan/40 flex items-center justify-center p-1.5 shadow-glow">
              <img src="/shield-logo.png" alt="Emblem" className="w-full h-full object-contain filter drop-shadow-[0_0_6px_#00d2ff]" />
            </div>
            <h1 className="text-2xl font-bold font-mono tracking-wide text-slate-100 flex items-center gap-2">
              CYBER<span className="text-cyber-cyan">SPLOI</span> PEN HUB RESEARCH COMMUNITY
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-cyan animate-pulse shadow-[0_0_8px_#00d2ff]"></span>
            Curated Threat Advisories, Defense Playbooks, and Offensive Exploit Case Studies
          </p>
        </div>
        <Button
          variant="primary"
          size="sm"
          onClick={() => setShowPublishForm(!showPublishForm)}
        >
          <PlusIcon className="w-4 h-4 mr-1.5" />
          {showPublishForm ? "Cancel" : "Publish Playbook"}
        </Button>
      </div>

      {showPublishForm && (
        <Card className="border-cyber-teal bg-cyber-teal/5">
          <CardHeader>
            <CardTitle>PUBLISH ADVISORY OR PLAYBOOK</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handlePublish} className="space-y-4">
              <Input
                label="Advisory Title"
                placeholder="e.g. Bypassing Spring Security Path Filters via URL Encoding"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                required
              />
              <div>
                <label className="block text-xs font-mono text-slate-400 mb-1">
                  Analysis & Summary
                </label>
                <textarea
                  className="w-full bg-background-card border border-border rounded-md p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyber-teal"
                  rows={3}
                  placeholder="Provide technical walkthrough, affected versions, and mitigation..."
                  value={newSummary}
                  onChange={(e) => setNewSummary(e.target.value)}
                  required
                />
              </div>
              <div className="flex justify-end gap-3">
                <Button type="button" variant="secondary" size="sm" onClick={() => setShowPublishForm(false)}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary" size="sm" isLoading={publishing}>
                  Submit to Peer Hub
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Main Feed */}
        <div className="md:col-span-2 space-y-4">
          {posts.map((post) => (
            <Card key={post.id} className="hover:border-slate-600 transition-colors">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Badge variant="info">{post.category}</Badge>
                  <span className="text-xs font-mono text-slate-500">• {post.date}</span>
                </div>
                <button
                  onClick={() => toast.success("Saved", "Playbook bookmarked.")}
                  className="text-slate-400 hover:text-cyber-teal p-1"
                >
                  <BookmarkIcon className="w-4 h-4" />
                </button>
              </CardHeader>
              <CardContent className="space-y-3">
                <h3 className="text-lg font-bold text-slate-100 hover:text-cyber-teal cursor-pointer transition-colors flex items-center justify-between">
                  <span>{post.title}</span>
                  <ArrowUpRightIcon className="w-4 h-4 flex-shrink-0 text-slate-500" />
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">{post.summary}</p>
                <div className="flex items-center justify-between pt-3 border-t border-border-muted text-xs font-mono text-slate-400">
                  <span>By {post.author}</span>
                  <div className="flex items-center gap-3">
                    <span>{post.reads} views</span>
                    <span className="flex items-center gap-1">
                      <ChatBubbleLeftRightIcon className="w-3.5 h-3.5" /> 18
                    </span>
                  </div>
                </div>
                <div className="flex gap-1.5 pt-1">
                  {post.tags.map((tag) => (
                    <span
                      key={tag}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-background-subtle border border-border text-slate-400"
                    >
                      #{tag}
                    </span>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Sidebar Info */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>ABOUT PEN HUB</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 text-xs font-mono text-slate-300 leading-relaxed">
              <p>
                Pen Hub is CYBERSPLOI’s collaborative security intelligence network connecting defensive engineers and offensive researchers.
              </p>
              <p className="text-slate-400">
                All playbooks undergo automated YARA and signature safety scanning prior to peer distribution.
              </p>
              <div className="p-3 rounded bg-cyber-teal/10 border border-cyber-teal/30 text-cyber-teal">
                Featured: Verified ethical penetration testing methodology compliant with NIST SP 800-115.
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
